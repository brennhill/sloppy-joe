//! The gateway for files whose bytes decide what gets installed (manifests, lockfiles and the
//! config the package managers read). Every such file is read through [`read`] / [`read_text`]:
//! the caller names the format, and input the scan cannot model is refused instead of being read
//! differently from the tool that will consume it. See docs/specs/untrusted-input-hardening.md.
//!
//! Refused for every format: a byte order mark, a NUL byte, invalid UTF-8 (ISO-8859-1 for
//! `Properties`), symlinks, non-regular files and files over the size limit. Refused for the
//! line-oriented formats: line terminators other than `\n` and `\r\n`. Refused for the
//! structured formats: duplicate keys (JSON, TOML, YAML), and in YAML also anchors, aliases,
//! merge keys and multiple documents.

use anyhow::{Result, bail};

/// Toml, Json, Yaml and Xml are consumed by later rollout steps (config surfaces, ambient inputs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Format {
    /// Lockfiles, `go.mod`, `Gemfile`, `.npmrc`, requirements: read line by line.
    Line,
    /// `java.util.Properties` files; a lone `\r` is a terminator the parser models.
    Properties,
    /// Build scripts and `setup.py`: lexed, with the line-terminator rules of `Line`.
    Script,
    Toml,
    Json,
    Yaml,
    Xml,
    /// Anything else: only the universal checks.
    Text,
}

/// The structured variants are consumed by later rollout steps (config surfaces, ambient inputs).
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum Untrusted {
    Text(String),
    Toml(toml::Value),
    Json(serde_json::Value),
    Yaml(serde_yaml::Value),
}

/// Read and validate `path`, parsing it when the format is structured.
pub(crate) fn read(path: &std::path::Path, format: Format, max_bytes: u64) -> Result<Untrusted> {
    let bytes = crate::fsutil::read_bytes_limited(path, max_bytes)?;
    parse(&bytes, format, path)
}

/// Like [`read`] for the formats whose content stays text.
pub(crate) fn read_text(path: &std::path::Path, format: Format, max_bytes: u64) -> Result<String> {
    if matches!(format, Format::Toml | Format::Json | Format::Yaml) {
        bail!(
            "{} is a structured format; read it with untrusted::read",
            path.display()
        );
    }
    match read(path, format, max_bytes)? {
        Untrusted::Text(text) => Ok(text),
        _ => unreachable!("text formats produce text"),
    }
}

/// A `java.util.Properties` file (`gradle.properties`, wrapper properties) as key/value pairs.
pub(crate) fn read_properties(path: &std::path::Path) -> Result<Vec<(String, String)>> {
    let bytes = crate::fsutil::read_bytes_limited(path, crate::fsutil::MAX_MANIFEST_BYTES)?;
    reject_unreadable_bytes(&bytes, path)?;
    Ok(crate::fsutil::parse_java_properties(&bytes))
}

/// A line-oriented manifest or lockfile with the standard size limit.
pub(crate) fn read_line_file(path: &std::path::Path) -> Result<String> {
    read_text(path, Format::Line, crate::fsutil::MAX_MANIFEST_BYTES)
}

/// A script (`setup.py`) with the standard size limit.
pub(crate) fn read_script_file(path: &std::path::Path) -> Result<String> {
    read_text(path, Format::Script, crate::fsutil::MAX_MANIFEST_BYTES)
}

/// Validate and parse bytes that were already read from `path`.
pub(crate) fn parse(bytes: &[u8], format: Format, path: &std::path::Path) -> Result<Untrusted> {
    reject_unreadable_bytes(bytes, path)?;
    let text = if format == Format::Properties {
        bytes.iter().map(|&b| b as char).collect()
    } else {
        String::from_utf8(bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("{} is not valid UTF-8: {e}", path.display()))?
    };
    if matches!(
        format,
        Format::Line | Format::Script | Format::Xml | Format::Yaml
    ) {
        crate::fsutil::reject_unmodeled_line_breaks(&text, path)?;
    }
    let invalid = |what: &str, err: &dyn std::fmt::Display| {
        anyhow::anyhow!("{} {what}: {err}", path.display())
    };
    Ok(match format {
        Format::Toml => {
            Untrusted::Toml(text.parse().map_err(|e| invalid("is not valid TOML", &e))?)
        }
        Format::Json => Untrusted::Json(
            strict_json::parse(&text).map_err(|e| invalid("is not acceptable JSON", &e))?,
        ),
        Format::Yaml => {
            yaml_scan::reject_aliasing(&text, path)?;
            Untrusted::Yaml(
                serde_yaml::from_str(&text).map_err(|e| invalid("is not acceptable YAML", &e))?,
            )
        }
        _ => Untrusted::Text(text),
    })
}

/// Split already validated line-oriented text. Use this instead of `str::lines()` so the
/// architecture test can tell a deliberate split from a new unreviewed one.
pub(crate) fn rows(text: &str) -> std::str::Lines<'_> {
    text.lines()
}

fn reject_unreadable_bytes(bytes: &[u8], path: &std::path::Path) -> Result<()> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        bail!(
            "{} starts with a byte order mark; the tool that reads it may treat it as part of the first key, so the file cannot be scanned reliably.",
            path.display()
        );
    }
    if let Some(at) = bytes.iter().position(|&b| b == 0) {
        bail!(
            "{} contains a NUL byte at offset {at}; tools truncate or skip text around it differently, so the file cannot be scanned reliably.",
            path.display()
        );
    }
    Ok(())
}

mod strict_json {
    use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number, Value};
    use std::fmt;

    struct Strict(Value);

    pub(super) fn parse(text: &str) -> Result<Value, serde_json::Error> {
        serde_json::from_str::<Strict>(text).map(|strict| strict.0)
    }

    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(StrictVisitor)
        }
    }

    struct StrictVisitor;

    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = Strict;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value")
        }

        fn visit_unit<E>(self) -> Result<Strict, E> {
            Ok(Strict(Value::Null))
        }

        fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
            Ok(Strict(Value::Bool(v)))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
            Ok(Strict(Value::Number(v.into())))
        }

        fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
            Ok(Strict(Value::Number(v.into())))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
            Number::from_f64(v)
                .map(|n| Strict(Value::Number(n)))
                .ok_or_else(|| E::custom("non-finite number"))
        }

        fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
            Ok(Strict(Value::String(v.to_string())))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
            let mut items = Vec::new();
            while let Some(Strict(item)) = seq.next_element()? {
                items.push(item);
            }
            Ok(Strict(Value::Array(items)))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
            let mut object = Map::new();
            while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                if object.insert(key.clone(), value).is_some() {
                    return Err(de::Error::custom(format!("duplicate key `{key}`")));
                }
            }
            Ok(Strict(Value::Object(object)))
        }
    }
}

/// serde_yaml resolves anchors and aliases silently and keeps `<<` as an ordinary key, while
/// other YAML readers merge. A conservative scan refuses all three. It tracks quoted scalars and
/// comments only, resets quote state at every line end (so a stray quote in a block scalar
/// cannot hide a later anchor), and may refuse a plain or block scalar that merely contains a
/// token-initial `&` or `*`: that is a false positive, never a pass.
mod yaml_scan {
    use anyhow::{Result, bail};

    pub(super) fn reject_aliasing(text: &str, path: &std::path::Path) -> Result<()> {
        for (number, line) in text.lines().enumerate() {
            if let Some(what) = aliasing_in_line(line) {
                bail!(
                    "{} line {}: YAML {what} is not supported; the tool that reads the file may resolve it differently than sloppy-joe, so it cannot be scanned reliably.",
                    path.display(),
                    number + 1
                );
            }
        }
        Ok(())
    }

    fn token_start(prev: Option<char>) -> bool {
        prev.is_none_or(|c| c.is_whitespace() || matches!(c, '[' | '{' | ',' | '-' | '?' | ':'))
    }

    fn aliasing_in_line(line: &str) -> Option<&'static str> {
        let chars: Vec<char> = line.chars().collect();
        let mut quote: Option<char> = None;
        let mut i = 0;
        while i < chars.len() {
            let prev = i.checked_sub(1).map(|p| chars[p]);
            let event = match quote {
                Some(q) => inside_quote(q, chars[i]),
                None => outside_quote(chars[i], prev, &chars[i..]),
            };
            match event {
                Event::Plain => {}
                Event::Escape => i += 1,
                Event::EndQuote => quote = None,
                Event::StartQuote(q) => quote = Some(q),
                Event::Comment => return None,
                Event::Found(what) => return Some(what),
            }
            i += 1;
        }
        None
    }

    enum Event {
        Plain,
        Escape,
        EndQuote,
        StartQuote(char),
        Comment,
        Found(&'static str),
    }

    fn inside_quote(quote: char, c: char) -> Event {
        if quote == '"' && c == '\\' {
            Event::Escape
        } else if c == quote {
            Event::EndQuote
        } else {
            Event::Plain
        }
    }

    fn outside_quote(c: char, prev: Option<char>, rest: &[char]) -> Event {
        let at_token = token_start(prev);
        if c == '#' && prev.is_none_or(char::is_whitespace) {
            Event::Comment
        } else if (c == '"' || c == '\'') && at_token {
            Event::StartQuote(c)
        } else if (c == '&' || c == '*') && at_token {
            Event::Found("anchor or alias")
        } else if c == '<' && at_token && is_merge_key(rest) {
            Event::Found("merge key")
        } else {
            Event::Plain
        }
    }

    fn is_merge_key(rest: &[char]) -> bool {
        rest.starts_with(&['<', '<'])
            && rest[2..]
                .iter()
                .find(|c| !c.is_whitespace())
                .is_some_and(|&c| c == ':')
    }
}

#[cfg(test)]
mod tests;

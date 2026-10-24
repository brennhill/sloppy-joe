//! Complexity of code that lives outside `fn` bodies: `static` / `const` initializers (a
//! `LazyLock<Box<dyn Fn>>` closure) and `macro_rules!` bodies.

use super::*;

/// Whether `b[at..]` starts the word `word`.
fn word_at(b: &[char], at: usize, word: &str) -> bool {
    let end = at + word.chars().count();
    b.get(at..end)
        .is_some_and(|got| got.iter().copied().eq(word.chars()))
        && (at == 0 || !is_ident(b[at - 1]))
        && !b.get(end).is_some_and(|c| is_ident(*c))
}

fn skip_space(b: &[char], mut at: usize) -> usize {
    while at < b.len() && b[at].is_whitespace() {
        at += 1;
    }
    at
}

fn ident_at(b: &[char], at: usize) -> (String, usize) {
    let mut end = at;
    while end < b.len() && is_ident(b[end]) {
        end += 1;
    }
    (b[at..end].iter().collect(), end)
}

/// `(name, complexity)` of every `static` / `const` initializer and `macro_rules!` body.
pub(crate) fn initializer_complexities(b: &[char]) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for i in 0..b.len() {
        if word_at(b, i, "macro_rules") {
            let mut at = skip_space(b, i + "macro_rules".len());
            if b.get(at) == Some(&'!') {
                at = skip_space(b, at + 1);
                let (name, after) = ident_at(b, at);
                if let Some(end) = block_end(b, skip_space(b, after)) {
                    found.push((name, complexity(&b[at..end])));
                }
            }
        } else if (word_at(b, i, "static") || word_at(b, i, "const")) && starts_item(b, i) {
            let keyword = if word_at(b, i, "static") { 6 } else { 5 };
            let mut at = skip_space(b, i + keyword);
            if word_at(b, at, "mut") {
                at = skip_space(b, at + 3);
            }
            let (name, after) = ident_at(b, at);
            if name.is_empty() || matches!(name.as_str(), "fn" | "unsafe" | "async" | "extern") {
                continue;
            }
            if b.get(skip_space(b, after)) == Some(&':') {
                found.push((name, complexity(&b[after..initializer_end(b, after)])));
            }
        }
    }
    found
}

/// A `const N: usize` generic parameter follows `<` or `,`; an item follows `;`, `}`, `{`, an
/// attribute, a visibility or the start of the file.
fn starts_item(b: &[char], at: usize) -> bool {
    let mut p = at;
    while p > 0 && b[p - 1].is_whitespace() {
        p -= 1;
    }
    p == 0 || !matches!(b[p - 1], '<' | ',')
}

/// End of the `{..}` block opening at `at`.
fn block_end(b: &[char], at: usize) -> Option<usize> {
    if b.get(at) != Some(&'{') {
        return None;
    }
    let mut depth = 0i32;
    for (offset, c) in b[at..].iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The `;` that ends an item starting at `from` (outside any bracket), or the end of the input.
fn initializer_end(b: &[char], from: usize) -> usize {
    let mut depth = 0i32;
    for (offset, c) in b[from..].iter().enumerate() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return from + offset;
                }
            }
            ';' if depth == 0 => return from + offset,
            _ => {}
        }
    }
    b.len()
}

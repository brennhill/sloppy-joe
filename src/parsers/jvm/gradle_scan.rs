use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GradleToken {
    Ident(String),
    Literal(String),
    Symbol(char),
}

/// Index just past the line comment starting at `i`. Groovy ends a line at a lone `\r` too.
fn skip_line_comment(chars: &[char], mut i: usize) -> usize {
    i += 2;
    while i < chars.len() && !matches!(chars[i], '\n' | '\r') {
        i += 1;
    }
    i
}

/// Index just past the block comment starting at `i`; unterminated comments run to the end.
fn skip_block_comment(chars: &[char], mut i: usize) -> usize {
    i += 2;
    while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
        i += 1;
    }
    (i + 2).min(chars.len())
}

/// Index just past the `${ ... }` interpolation whose `$` is at `i`; nested literals are skipped.
fn skip_interpolation(chars: &[char], mut i: usize) -> usize {
    i += 2;
    let mut depth = 1usize;
    while i < chars.len() && depth > 0 {
        match chars[i] {
            '{' => depth += 1,
            '}' => depth -= 1,
            '"' | '\'' => {
                i = skip_quoted_literal(chars, i);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    i.min(chars.len())
}

/// Index just past the triple-quoted literal (three single or three double quotes) starting at `i`.
fn skip_triple_literal(chars: &[char], mut i: usize) -> usize {
    let quote = chars[i];
    i += 3;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
        } else if quote == '"' && chars[i] == '$' && chars.get(i + 1) == Some(&'{') {
            i = skip_interpolation(chars, i);
        } else if chars[i] == quote
            && chars.get(i + 1) == Some(&quote)
            && chars.get(i + 2) == Some(&quote)
        {
            return i + 3;
        } else {
            i += 1;
        }
    }
    chars.len()
}

/// Index just past the slashy (`/.../`) or dollar-slashy (`$/.../$`) string starting at `i`.
fn skip_slashy_literal(chars: &[char], mut i: usize) -> usize {
    let dollar = chars[i] == '$';
    i += if dollar { 2 } else { 1 };
    while i < chars.len() {
        if chars[i] == '\\' && !dollar {
            i += 2;
        } else if dollar && chars[i] == '/' && chars.get(i + 1) == Some(&'$') {
            return i + 2;
        } else if !dollar && chars[i] == '/' {
            return i + 1;
        } else {
            i += 1;
        }
    }
    chars.len()
}

/// Groovy reads `/` as the start of a slashy string, not a division, unless the previous token
/// ends an expression (identifier, literal, closing bracket, number).
fn slashy_starts_here(tokens: &[GradleToken], chars: &[char], i: usize) -> bool {
    match chars[..i].iter().rev().find(|c| !c.is_whitespace()) {
        None => true,
        Some(c) if matches!(c, ')' | ']' | '}' | '"' | '\'') || c.is_ascii_digit() => false,
        Some(c) if c.is_ascii_alphanumeric() || *c == '_' => matches!(
            tokens.last(),
            Some(GradleToken::Ident(word))
                if matches!(word.as_str(), "return" | "case" | "in" | "assert" | "throw" | "else")
        ),
        Some(_) => true,
    }
}

/// Index just past the quoted literal starting at `i`; unterminated literals run to the end.
fn skip_quoted_literal(chars: &[char], mut i: usize) -> usize {
    let quote = chars[i];
    i += 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if quote == '"' && chars[i] == '$' && chars.get(i + 1) == Some(&'{') {
            i = skip_interpolation(chars, i);
            continue;
        }
        i += 1;
        if chars[i - 1] == quote {
            break;
        }
    }
    i.min(chars.len())
}

fn skip_identifier(chars: &[char], mut i: usize) -> usize {
    i += 1;
    while i < chars.len()
        && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '.' | '-' | ':'))
    {
        i += 1;
    }
    i
}

/// End of the string literal starting at `i`, if a literal starts there.
fn literal_end(tokens: &[GradleToken], chars: &[char], i: usize) -> Option<usize> {
    let next = chars.get(i + 1).copied();
    match chars[i] {
        '/' if slashy_starts_here(tokens, chars, i) => Some(skip_slashy_literal(chars, i)),
        '$' if next == Some('/') => Some(skip_slashy_literal(chars, i)),
        quote @ ('"' | '\'') => {
            let triple = next == Some(quote) && chars.get(i + 2) == Some(&quote);
            Some(if triple {
                skip_triple_literal(chars, i)
            } else {
                skip_quoted_literal(chars, i)
            })
        }
        _ => None,
    }
}

pub(crate) fn tokenize_gradle(content: &str) -> Vec<GradleToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let next = chars.get(i + 1).copied();
        let comment = chars[i] == '/' && matches!(next, Some('/' | '*'));
        if !comment && let Some(end) = literal_end(&tokens, &chars, i) {
            tokens.push(GradleToken::Literal(chars[i..end].iter().collect()));
            i = end;
            continue;
        }
        match chars[i] {
            '/' if next == Some('/') => i = skip_line_comment(&chars, i),
            '/' if next == Some('*') => i = skip_block_comment(&chars, i),
            c @ ('{' | '}' | '(' | ')') => {
                tokens.push(GradleToken::Symbol(c));
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let end = skip_identifier(&chars, i);
                tokens.push(GradleToken::Ident(chars[i..end].iter().collect()));
                i = end;
            }
            _ => i += 1,
        }
    }
    tokens
}

pub(crate) fn find_gradle_block_end(tokens: &[GradleToken], open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, token) in tokens.iter().enumerate().skip(open_idx) {
        match token {
            GradleToken::Symbol('{') => depth += 1,
            GradleToken::Symbol('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn validate_gradle_repositories_block(
    tokens: &[GradleToken],
    path: &Path,
) -> Result<bool> {
    let mut google_declared = false;
    for (idx, window) in tokens.windows(2).enumerate() {
        let [GradleToken::Ident(name), GradleToken::Symbol(next)] = window else {
            continue;
        };
        if !matches!(next, '{' | '(') {
            continue;
        }
        // A bare `google()` is Google's Maven repository; any option block or
        // argument could narrow or redirect it, so only the plain call is
        // understood.
        if name == "google"
            && *next == '('
            && matches!(tokens.get(idx + 2), Some(GradleToken::Symbol(')')))
            && !matches!(tokens.get(idx + 3), Some(GradleToken::Symbol('{')))
        {
            google_declared = true;
            continue;
        }
        if matches!(
            name.as_str(),
            "maven" | "mavenLocal" | "flatDir" | "ivy" | "google" | "gradlePluginPortal"
        ) {
            bail!(
                "Unsupported Gradle repository in {}: only mavenCentral() and google() are supported for trusted registry resolution",
                path.display()
            );
        }
    }
    Ok(google_declared)
}

/// `buildscript { dependencies { classpath 'g:a:v' } }`: build tooling pinned
/// to literal, exact coordinates. Anything else cannot be verified.
pub(crate) fn parse_classpath_block(
    tokens: &[GradleToken],
    path: &Path,
) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        match &tokens[idx] {
            GradleToken::Ident(name) if name == "classpath" => {
                let next = idx
                    + 1
                    + usize::from(matches!(
                        tokens.get(idx + 1),
                        Some(GradleToken::Symbol('('))
                    ));
                let Some(GradleToken::Literal(literal)) = tokens.get(next) else {
                    bail!(
                        "Unsupported Gradle buildscript classpath in {}: expected literal coordinates",
                        path.display()
                    );
                };
                let dep = extract_gradle_dep(literal, path)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Gradle buildscript classpath notation in {}",
                        path.display()
                    )
                })?;
                crate::parsers::validate_dependency(&dep, path)?;
                // Gradle's dynamic selectors (`8.+`, `latest.release`) are not literal
                // releases even though they contain no range brackets.
                let pinned = dep.version.as_deref().is_some_and(|version| {
                    !version.is_empty()
                        && !version.starts_with("latest.")
                        && version
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                });
                if !pinned {
                    bail!(
                        "Unsupported Gradle buildscript classpath '{}' in {}: buildscript dependencies are not locked, so they must pin an exact version",
                        crate::report::sanitize_for_terminal(&dep.name),
                        path.display()
                    );
                }
                deps.push(dep);
                idx = next;
            }
            GradleToken::Symbol(_) | GradleToken::Literal(_) => {}
            GradleToken::Ident(name) => bail!(
                "Unsupported Gradle buildscript dependency expression '{}' in {}: only literal classpath coordinates can be verified",
                crate::report::sanitize_for_terminal(name),
                path.display()
            ),
        }
        idx += 1;
    }
    Ok(deps)
}

pub(crate) fn validate_gradle_dependencies_block(
    tokens: &[GradleToken],
    path: &Path,
) -> Result<()> {
    for token in tokens {
        let GradleToken::Ident(name) = token else {
            continue;
        };
        if ["project", "files", "fileTree", "includeBuild"].contains(&name.as_str()) {
            bail!(
                "Unsupported Gradle dependency source in {}: local project or file dependencies are not supported",
                path.display()
            );
        }
        if !GRADLE_DEPENDENCY_CONFIGS.contains(&name.as_str()) {
            bail!(
                "Unsupported Gradle dependency expression '{}' in {}: only literal coordinates in supported configurations can be verified",
                name,
                path.display()
            );
        }
    }
    Ok(())
}

/// Plugins bundled with the Gradle distribution. They are not downloaded from
/// any repository, so they carry no supply-chain risk for this scanner.
pub(crate) const GRADLE_CORE_PLUGINS: &[&str] = &[
    "antlr",
    "application",
    "assembler",
    "base",
    "build-dashboard",
    "build-init",
    "c",
    "checkstyle",
    "codenarc",
    "cpp",
    "cpp-application",
    "cpp-library",
    "cpp-unit-test",
    "distribution",
    "ear",
    "eclipse",
    "eclipse-wtp",
    "groovy",
    "groovy-base",
    "help-tasks",
    "idea",
    "ivy-publish",
    "jacoco",
    "jacoco-report-aggregation",
    "java",
    "java-base",
    "java-gradle-plugin",
    "java-library",
    "java-library-distribution",
    "java-platform",
    "java-test-fixtures",
    "jvm-test-suite",
    "maven-publish",
    "objective-c",
    "objective-cpp",
    "pmd",
    "project-report",
    "publishing",
    "reporting-base",
    "scala",
    "scala-base",
    "signing",
    "swift-application",
    "swift-library",
    "test-report-aggregation",
    "version-catalog",
    "visual-studio",
    "war",
    "windows-resources",
    "wrapper",
    "xcode",
    "xctest",
];

pub(crate) fn is_gradle_core_plugin(id: &str) -> bool {
    let short = id.strip_prefix("org.gradle.").unwrap_or(id);
    GRADLE_CORE_PLUGINS.contains(&short)
}

pub(crate) fn gradle_literal_value(literal: &str) -> Option<&str> {
    let quote = literal.chars().next()?;
    if !matches!(quote, '\'' | '"') || literal.len() < 2 || !literal.ends_with(quote) {
        return None;
    }
    let value = &literal[1..literal.len() - 1];
    // Interpolation and escapes make the effective plugin id unknowable.
    (!value.contains(['$', '\\'])).then_some(value)
}

pub(crate) fn scan_gradle_script(
    content: &str,
    path: &Path,
) -> Result<gradle_plugins::GradleScript> {
    let tokens = tokenize_gradle(content);
    let mut script = gradle_plugins::GradleScript::default();
    walk_gradle_script(&tokens, path, &mut script, false, false)?;
    Ok(script)
}

/// Which enclosing block a Gradle script walk is inside.
#[derive(Clone, Copy)]
struct GradleScope {
    plugin_management: bool,
    buildscript: bool,
}

/// `getRepositories()`, `getBuildscript().repositories` and friends reach the same models as the
/// property syntax but would slip past the name checks.
fn reject_getter_forms(name: &str, path: &Path) -> Result<()> {
    for part in name.split('.') {
        let Some(target) = part
            .strip_prefix("get")
            .or_else(|| part.strip_prefix("set"))
        else {
            continue;
        };
        if matches!(
            target.to_ascii_lowercase().as_str(),
            "repositories"
                | "dependencies"
                | "pluginmanagement"
                | "buildscript"
                | "resolutionstrategy"
        ) {
            bail!(
                "Unsupported Gradle accessor '{}' in {}: repositories and dependencies can only be verified when declared in literal blocks",
                crate::report::sanitize_for_terminal(name),
                path.display()
            );
        }
    }
    Ok(())
}

/// Fail closed on constructs that can change dependencies or repositories outside literal blocks.
fn reject_unverifiable_ident(name: &str, opens_block: bool, path: &Path) -> Result<()> {
    reject_getter_forms(name, path)?;
    let mut parts = name.split('.');
    if parts.clone().any(|part| part == "dependencies") && (name != "dependencies" || !opens_block)
    {
        bail!(
            "Unsupported Gradle dependency expression in {}: dependency mutations outside literal blocks cannot be verified",
            path.display()
        );
    }
    if parts.any(|part| matches!(part, "repositories" | "pluginManagement"))
        && (!matches!(name, "repositories" | "pluginManagement") || !opens_block)
    {
        bail!(
            "Unsupported Gradle repository expression '{}' in {}: repositories can only be verified when declared in literal blocks",
            crate::report::sanitize_for_terminal(name),
            path.display()
        );
    }
    if name == "resolutionStrategy" || name.starts_with("resolutionStrategy.") {
        bail!(
            "Unsupported Gradle resolution rule in {}: resolutionStrategy can substitute or force dependency versions that cannot be verified",
            path.display()
        );
    }
    if matches!(name, "apply" | "includeBuild") {
        bail!(
            "Unsupported Gradle script source '{}' in {}: applied scripts and composite builds cannot be verified",
            name,
            path.display()
        );
    }
    Ok(())
}

/// Handle the block opened by `tokens[idx]`; returns the index of its closing brace when consumed.
fn walk_gradle_block(
    tokens: &[GradleToken],
    idx: usize,
    name: &str,
    path: &Path,
    script: &mut gradle_plugins::GradleScript,
    scope: GradleScope,
) -> Result<Option<usize>> {
    let handled = match name {
        "pluginManagement" => true,
        "buildscript" => !scope.buildscript,
        "plugins" | "repositories" | "dependencies" => true,
        _ => false,
    };
    if !handled {
        return Ok(None);
    }
    let end = find_gradle_block_end(tokens, idx + 1).ok_or_else(|| {
        anyhow::anyhow!(
            "Broken Gradle manifest '{}': unclosed '{}' block.",
            path.display(),
            name
        )
    })?;
    let block = &tokens[idx + 2..end];
    match name {
        "pluginManagement" => {
            script.has_plugin_management = true;
            walk_gradle_script(block, path, script, true, false)?;
        }
        "buildscript" => walk_gradle_script(block, path, script, false, true)?,
        "plugins" => {
            let plugins = gradle_plugins::parse_plugins_block(block, path)?;
            if scope.plugin_management {
                script.managed_plugins.extend(plugins);
            } else {
                script.plugins.extend(plugins);
            }
        }
        "dependencies" if scope.buildscript => {
            script.classpath.extend(parse_classpath_block(block, path)?);
        }
        "dependencies" => validate_gradle_dependencies_block(block, path)?,
        _ => walk_repositories_block(block, path, script, scope)?,
    }
    Ok(Some(end))
}

fn walk_repositories_block(
    block: &[GradleToken],
    path: &Path,
    script: &mut gradle_plugins::GradleScript,
    scope: GradleScope,
) -> Result<()> {
    if scope.plugin_management {
        script
            .plugin_repositories
            .get_or_insert_with(Vec::new)
            .extend(gradle_plugins::parse_plugin_repositories(block, path)?);
        return Ok(());
    }
    let google = validate_gradle_repositories_block(block, path)?;
    if scope.buildscript {
        script.buildscript_uses_google |= google;
    } else {
        script.uses_google_maven |= google;
    }
    Ok(())
}

/// Enforce the Gradle source policy over `tokens` and collect plugin requests.
/// `plugin_management` is set inside a `pluginManagement { }` block, where
/// `repositories` and `plugins` configure plugin resolution.
pub(crate) fn walk_gradle_script(
    tokens: &[GradleToken],
    path: &Path,
    script: &mut gradle_plugins::GradleScript,
    plugin_management: bool,
    buildscript: bool,
) -> Result<()> {
    let mut idx = 0usize;
    while idx < tokens.len() {
        let opens_block = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{')));
        let GradleToken::Ident(name) = &tokens[idx] else {
            idx += 1;
            continue;
        };
        reject_unverifiable_ident(name, opens_block, path)?;
        if name
            .split('.')
            .any(|part| matches!(part, "versionCatalogs" | "defaultLibrariesExtensionName"))
        {
            script.custom_catalogs = true;
        }
        if opens_block {
            let scope = GradleScope {
                plugin_management,
                buildscript,
            };
            if let Some(end) = walk_gradle_block(tokens, idx, name, path, script, scope)? {
                idx = end;
            }
        }
        idx += 1;
    }

    Ok(())
}

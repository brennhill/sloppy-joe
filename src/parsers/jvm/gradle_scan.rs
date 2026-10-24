use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GradleToken {
    Ident(String),
    Literal(String),
    Symbol(char),
}

pub(crate) fn tokenize_gradle(content: &str) -> Vec<GradleToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(chars.len());
            }
            '"' | '\'' => {
                let start = i;
                let quote = chars[i];
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                tokens.push(GradleToken::Literal(
                    chars[start..i.min(chars.len())].iter().collect(),
                ));
            }
            '{' | '}' | '(' | ')' => {
                tokens.push(GradleToken::Symbol(chars[i]));
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || matches!(chars[i], '_' | '.' | '-' | ':'))
                {
                    i += 1;
                }
                tokens.push(GradleToken::Ident(chars[start..i].iter().collect()));
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
    let block_end = |idx: usize, name: &str| {
        find_gradle_block_end(tokens, idx + 1).ok_or_else(|| {
            anyhow::anyhow!(
                "Broken Gradle manifest '{}': unclosed '{}' block.",
                path.display(),
                name
            )
        })
    };
    let mut idx = 0usize;
    while idx < tokens.len() {
        let opens_block = matches!(tokens.get(idx + 1), Some(GradleToken::Symbol('{')));
        match &tokens[idx] {
            GradleToken::Ident(name)
                if name.split('.').any(|part| part == "dependencies")
                    && (name != "dependencies" || !opens_block) =>
            {
                bail!(
                    "Unsupported Gradle dependency expression in {}: dependency mutations outside literal blocks cannot be verified",
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name
                    .split('.')
                    .any(|part| matches!(part, "repositories" | "pluginManagement"))
                    && (!matches!(name.as_str(), "repositories" | "pluginManagement")
                        || !opens_block) =>
            {
                bail!(
                    "Unsupported Gradle repository expression '{}' in {}: repositories can only be verified when declared in literal blocks",
                    crate::report::sanitize_for_terminal(name),
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name == "resolutionStrategy" || name.starts_with("resolutionStrategy.") =>
            {
                bail!(
                    "Unsupported Gradle resolution rule in {}: resolutionStrategy can substitute or force dependency versions that cannot be verified",
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if name.split('.').any(|part| {
                    matches!(part, "versionCatalogs" | "defaultLibrariesExtensionName")
                }) =>
            {
                script.custom_catalogs = true;
            }
            GradleToken::Ident(name) if name == "pluginManagement" && opens_block => {
                let end = block_end(idx, name)?;
                script.has_plugin_management = true;
                walk_gradle_script(&tokens[idx + 2..end], path, script, true, false)?;
                idx = end;
            }
            GradleToken::Ident(name) if name == "buildscript" && opens_block && !buildscript => {
                let end = block_end(idx, name)?;
                walk_gradle_script(&tokens[idx + 2..end], path, script, false, true)?;
                idx = end;
            }
            GradleToken::Ident(name) if name == "plugins" && opens_block => {
                let end = block_end(idx, name)?;
                let plugins = gradle_plugins::parse_plugins_block(&tokens[idx + 2..end], path)?;
                if plugin_management {
                    script.managed_plugins.extend(plugins);
                } else {
                    script.plugins.extend(plugins);
                }
                idx = end;
            }
            GradleToken::Ident(name) if matches!(name.as_str(), "apply" | "includeBuild") => {
                bail!(
                    "Unsupported Gradle script source '{}' in {}: applied scripts and composite builds cannot be verified",
                    name,
                    path.display()
                );
            }
            GradleToken::Ident(name)
                if matches!(name.as_str(), "repositories" | "dependencies") && opens_block =>
            {
                let end = block_end(idx, name)?;
                let block = &tokens[idx + 2..end];
                if name == "dependencies" && buildscript {
                    script.classpath.extend(parse_classpath_block(block, path)?);
                } else if name == "dependencies" {
                    validate_gradle_dependencies_block(block, path)?;
                } else if plugin_management {
                    script
                        .plugin_repositories
                        .get_or_insert_with(Vec::new)
                        .extend(gradle_plugins::parse_plugin_repositories(block, path)?);
                } else {
                    let google = validate_gradle_repositories_block(block, path)?;
                    if buildscript {
                        script.buildscript_uses_google |= google;
                    } else {
                        script.uses_google_maven |= google;
                    }
                }
                idx = end;
            }
            _ => {}
        }
        idx += 1;
    }

    Ok(())
}

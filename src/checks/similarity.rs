use crate::report::{Issue, Severity};
use crate::Dependency;

/// Placeholder popular package lists per ecosystem.
fn popular_packages(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &[
            "react", "express", "lodash", "axios", "webpack", "typescript",
            "next", "vue", "angular", "moment", "chalk", "commander",
            "debug", "uuid", "dotenv", "cors", "jsonwebtoken", "mongoose",
            "socket.io", "jest",
        ],
        "pypi" => &[
            "requests", "numpy", "pandas", "flask", "django", "pytest",
            "scipy", "matplotlib", "pillow", "sqlalchemy", "celery",
            "fastapi", "pydantic", "httpx", "uvicorn", "gunicorn",
            "boto3", "selenium", "scrapy", "beautifulsoup4",
        ],
        "cargo" => &[
            "serde", "tokio", "clap", "reqwest", "anyhow", "thiserror",
            "rand", "regex", "chrono", "hyper", "actix-web", "axum",
            "tracing", "log", "futures", "syn", "quote", "proc-macro2",
            "bytes", "tower",
        ],
        "go" => &[
            "github.com/gin-gonic/gin", "github.com/labstack/echo",
            "github.com/gofiber/fiber", "github.com/spf13/cobra",
            "github.com/spf13/viper", "go.uber.org/zap",
            "github.com/sirupsen/logrus", "gorm.io/gorm",
            "github.com/go-chi/chi", "github.com/gorilla/mux",
            "github.com/stretchr/testify", "github.com/go-redis/redis",
            "google.golang.org/grpc", "github.com/golang-jwt/jwt",
            "github.com/jackc/pgx", "github.com/nats-io/nats.go",
            "github.com/rs/zerolog", "github.com/valyala/fasthttp",
            "github.com/prometheus/client_golang", "github.com/hashicorp/consul",
        ],
        "ruby" => &[
            "rails", "puma", "sidekiq", "devise", "rspec", "rubocop",
            "faker", "nokogiri", "pg", "redis", "rack", "sinatra",
            "capybara", "bcrypt", "aws-sdk", "activerecord", "bundler",
            "rspec-rails", "factory_bot", "webpacker",
        ],
        "php" => &[
            "laravel/framework", "symfony/console", "guzzlehttp/guzzle",
            "phpunit/phpunit", "monolog/monolog", "doctrine/orm",
            "league/flysystem", "vlucas/phpdotenv", "predis/predis",
            "phpstan/phpstan", "symfony/http-foundation", "nikic/fast-route",
            "ramsey/uuid", "twig/twig", "carbon/carbon",
            "intervention/image", "spatie/laravel-permission",
            "filp/whoops", "mockery/mockery", "barryvdh/laravel-debugbar",
        ],
        "jvm" => &[
            "com.google.guava:guava", "org.springframework:spring-core",
            "junit:junit", "org.apache.commons:commons-lang3",
            "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
            "com.fasterxml.jackson.core:jackson-databind",
            "org.projectlombok:lombok", "org.mockito:mockito-core",
            "io.netty:netty-all", "org.jetbrains.kotlin:kotlin-stdlib",
            "com.squareup.okhttp3:okhttp", "io.grpc:grpc-core",
            "org.apache.kafka:kafka-clients", "com.google.code.gson:gson",
            "org.hibernate:hibernate-core", "org.assertj:assertj-core",
            "io.micrometer:micrometer-core", "com.zaxxer:HikariCP",
            "org.apache.httpcomponents:httpclient",
        ],
        "dotnet" => &[
            "Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection",
            "xunit", "Serilog", "AutoMapper", "MediatR",
            "FluentValidation", "Dapper", "Polly", "Moq",
            "Swashbuckle.AspNetCore", "StackExchange.Redis",
            "Microsoft.EntityFrameworkCore", "NUnit", "FluentAssertions",
            "Bogus", "Hangfire", "MassTransit",
            "Microsoft.Extensions.Logging", "Npgsql",
        ],
        _ => &[],
    }
}

/// Max allowed edit distance, scaled by name length.
fn max_distance(name_len: usize) -> usize {
    match name_len {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

/// Returns true if the registry treats package names as case-insensitive.
/// Case-insensitive registries: npm, pypi, cargo, nuget, packagist.
/// Case-sensitive registries: go, jvm (maven), ruby.
fn is_case_insensitive(ecosystem: &str) -> bool {
    matches!(ecosystem, "npm" | "pypi" | "cargo" | "dotnet" | "php")
}

/// Check each dependency name against popular packages for suspiciously similar names.
///
/// Two checks:
/// 1. Levenshtein distance (catches typosquats like "requsets")
/// 2. Case-variant detection (catches "newtonsoft.json" when "Newtonsoft.Json" is canonical)
///
/// On case-insensitive registries (npm, pypi, cargo, nuget, php), only exact
/// case-insensitive match skips the check — the registry prevents case-variant attacks.
///
/// On case-sensitive registries (go, maven, ruby), only exact case-sensitive match
/// skips the check. A case variant is flagged as a potential typosquat because
/// someone could register the variant as a separate, malicious package.
pub fn check_similarity(deps: &[Dependency], ecosystem: &str) -> Vec<Issue> {
    let popular = popular_packages(ecosystem);
    let case_insensitive = is_case_insensitive(ecosystem);
    let mut issues = Vec::new();

    for dep in deps {
        for &pop in popular {
            // Exact match (case-sensitive) — always safe, skip
            if dep.name == pop {
                continue;
            }

            // Case-insensitive match on a case-insensitive registry — safe, skip
            if case_insensitive && dep.name.to_lowercase() == pop.to_lowercase() {
                continue;
            }

            // Case-sensitive registry: flag case variants as typosquats
            if !case_insensitive && dep.name.to_lowercase() == pop.to_lowercase() {
                issues.push(Issue {
                    package: dep.name.clone(),
                    check: "similarity".to_string(),
                    severity: Severity::Error,
                    message: format!(
                        "'{}' differs from '{}' only in letter casing. On case-sensitive registries ({}) these resolve to different packages. An attacker could register the case variant as a malicious package.",
                        dep.name, pop, ecosystem
                    ),
                    fix: format!(
                        "Use the exact casing '{}' in your manifest. Case variants on case-sensitive registries are a known attack vector.",
                        pop
                    ),
                    suggestion: Some(pop.to_string()),
                    registry_url: None,
                });
                break;
            }

            // Levenshtein distance check (case-insensitive comparison)
            let dep_lower = dep.name.to_lowercase();
            let pop_lower = pop.to_lowercase();
            let threshold = max_distance(dep_lower.len());
            let distance = strsim::levenshtein(&dep_lower, &pop_lower);
            if distance <= threshold {
                issues.push(Issue {
                    package: dep.name.clone(),
                    check: "similarity".to_string(),
                    severity: Severity::Warning,
                    message: format!(
                        "'{}' is only {} character{} away from the popular package '{}'. This could be a typosquat — a malicious package with a name designed to trick you into installing it instead of the real one.",
                        dep.name, distance, if distance == 1 { "" } else { "s" }, pop
                    ),
                    fix: format!(
                        "If you meant '{}', fix the name in your manifest. If '{}' is intentional and legitimate, add it to the 'allowed' list in your sloppy-joe config.",
                        pop, dep.name
                    ),
                    suggestion: Some(pop.to_string()),
                    registry_url: None,
                });
                break;
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }
    }

    #[test]
    fn exact_match_produces_no_issue() {
        let deps = vec![dep("react")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn levenshtein_1_on_short_name_flags() {
        let deps = vec![dep("reac")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].suggestion, Some("react".to_string()));
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(!issues[0].fix.is_empty());
    }

    #[test]
    fn levenshtein_2_on_short_name_does_not_flag() {
        let deps = vec![dep("zzzz")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn levenshtein_2_on_medium_name_flags() {
        let deps = vec![dep("expresz")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    #[test]
    fn levenshtein_3_on_medium_name_does_not_flag() {
        let deps = vec![dep("abcdefg")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn completely_unrelated_name_no_issue() {
        let deps = vec![dep("zzzzzzzzzzzzz")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn max_distance_thresholds() {
        assert_eq!(max_distance(0), 1);
        assert_eq!(max_distance(1), 1);
        assert_eq!(max_distance(4), 1);
        assert_eq!(max_distance(5), 2);
        assert_eq!(max_distance(8), 2);
        assert_eq!(max_distance(9), 3);
        assert_eq!(max_distance(20), 3);
    }

    #[test]
    fn unknown_ecosystem_returns_no_issues() {
        let deps = vec![dep("anything")];
        let issues = check_similarity(&deps, "unknown");
        assert!(issues.is_empty());
    }

    #[test]
    fn popular_packages_returns_entries_for_known_ecosystems() {
        assert!(!popular_packages("npm").is_empty());
        assert!(!popular_packages("pypi").is_empty());
        assert!(!popular_packages("cargo").is_empty());
        assert!(!popular_packages("go").is_empty());
        assert!(!popular_packages("ruby").is_empty());
        assert!(!popular_packages("php").is_empty());
        assert!(!popular_packages("jvm").is_empty());
        assert!(!popular_packages("dotnet").is_empty());
        assert!(popular_packages("unknown").is_empty());
    }

    // --- Case-sensitivity tests ---

    fn dep_eco(name: &str, ecosystem: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: ecosystem.to_string(),
        }
    }

    #[test]
    fn case_insensitive_registry_skips_case_variant() {
        // npm is case-insensitive: "React" should match "react" and be skipped
        let deps = vec![dep("React")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn case_insensitive_registry_dotnet_skips_exact() {
        // "Newtonsoft.Json" exact match to popular list — no issue
        let deps = vec![dep_eco("Newtonsoft.Json", "dotnet")];
        let issues = check_similarity(&deps, "dotnet");
        assert!(issues.is_empty());
    }

    #[test]
    fn case_insensitive_registry_dotnet_skips_case_variant() {
        // dotnet is case-insensitive: "newtonsoft.json" resolves to same package
        let deps = vec![dep_eco("newtonsoft.json", "dotnet")];
        let issues = check_similarity(&deps, "dotnet");
        assert!(issues.is_empty());
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_go() {
        // Go is case-sensitive: "github.com/Gin-Gonic/Gin" is NOT the same as
        // "github.com/gin-gonic/gin" — an attacker could register the variant
        let deps = vec![dep_eco("github.com/Gin-Gonic/Gin", "go")];
        let issues = check_similarity(&deps, "go");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("case-sensitive"));
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_ruby() {
        // Ruby is case-sensitive: "Rails" != "rails"
        let deps = vec![dep_eco("Rails", "ruby")];
        let issues = check_similarity(&deps, "ruby");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].suggestion, Some("rails".to_string()));
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_jvm() {
        // Maven is case-sensitive: "Junit:Junit" != "junit:junit"
        let deps = vec![dep_eco("Junit:Junit", "jvm")];
        let issues = check_similarity(&deps, "jvm");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn case_sensitive_registry_exact_match_no_issue() {
        // Exact match on case-sensitive registry — no issue
        let deps = vec![dep_eco("rails", "ruby")];
        let issues = check_similarity(&deps, "ruby");
        assert!(issues.is_empty());
    }

    #[test]
    fn is_case_insensitive_correct() {
        assert!(is_case_insensitive("npm"));
        assert!(is_case_insensitive("pypi"));
        assert!(is_case_insensitive("cargo"));
        assert!(is_case_insensitive("dotnet"));
        assert!(is_case_insensitive("php"));
        assert!(!is_case_insensitive("go"));
        assert!(!is_case_insensitive("jvm"));
        assert!(!is_case_insensitive("ruby"));
    }
}

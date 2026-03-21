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

/// Check each dependency name against popular packages for suspiciously similar names.
pub fn check_similarity(deps: &[Dependency], ecosystem: &str) -> Vec<Issue> {
    let popular = popular_packages(ecosystem);
    let mut issues = Vec::new();

    for dep in deps {
        let dep_name = dep.name.to_lowercase();
        let threshold = max_distance(dep_name.len());
        for &pop in popular {
            if dep_name == pop {
                continue;
            }
            let distance = strsim::levenshtein(&dep_name, pop);
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
}

use crate::cache;
use std::path::PathBuf;

const CACHE_TTL_SECS: u64 = 24 * 3600; // 24 hours

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CorpusCache {
    timestamp: u64,
    packages: Vec<String>,
}

fn cache_path(ecosystem: &str) -> PathBuf {
    cache::user_cache_dir()
        .join("sloppy-joe")
        .join(format!("corpus-{}.json", ecosystem))
}

fn load_cached(ecosystem: &str) -> Option<Vec<String>> {
    let path = cache_path(ecosystem);
    let cache =
        cache::read_json_cache::<CorpusCache>(&path, CACHE_TTL_SECS, |c| c.timestamp)?;
    if cache.packages.is_empty() {
        None
    } else {
        Some(cache.packages)
    }
}

fn save_cached(ecosystem: &str, packages: &[String]) {
    let path = cache_path(ecosystem);
    let cache = CorpusCache {
        timestamp: cache::now_epoch(),
        packages: packages.to_vec(),
    };
    let _ = cache::atomic_write_json(&path, &cache);
}

/// Fetch the popular packages corpus for an ecosystem.
/// Uses a 24-hour disk cache. On fetch failure, falls back to a hardcoded list.
pub async fn fetch_popular(ecosystem: &str) -> Vec<String> {
    // Try disk cache first
    if let Some(cached) = load_cached(ecosystem) {
        return cached;
    }

    let client = super::http_client();

    // Try fetching from registry API
    let fetched = match ecosystem {
        "npm" => fetch_npm_popular(&client).await,
        "cargo" => fetch_crates_popular(&client).await,
        "php" => fetch_packagist_popular(&client).await,
        "dotnet" => fetch_nuget_popular(&client).await,
        _ => None,
    };

    if let Some(packages) = fetched.filter(|p| !p.is_empty()) {
        save_cached(ecosystem, &packages);
        return packages;
    }

    // Fall back to hardcoded list
    fallback_popular(ecosystem)
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// npm: search with popularity boost (up to 250)
async fn fetch_npm_popular(client: &reqwest::Client) -> Option<Vec<String>> {
    let url = "https://registry.npmjs.org/-/v1/search?text=boost-exact:false&popularity=1.0&quality=0.0&maintenance=0.0&size=250";
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let packages = body["objects"]
        .as_array()?
        .iter()
        .filter_map(|obj| obj["package"]["name"].as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    if packages.is_empty() {
        None
    } else {
        Some(packages)
    }
}

/// crates.io: sort by downloads (2 pages of 100)
async fn fetch_crates_popular(client: &reqwest::Client) -> Option<Vec<String>> {
    let mut all = Vec::new();
    for page in 1..=2 {
        let url = format!(
            "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={}",
            page
        );
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            break;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let crates = body["crates"].as_array()?;
        for krate in crates {
            if let Some(name) = krate["id"].as_str() {
                all.push(name.to_string());
            }
        }
    }
    if all.is_empty() { None } else { Some(all) }
}

/// Packagist: search sorted by downloads
async fn fetch_packagist_popular(client: &reqwest::Client) -> Option<Vec<String>> {
    let mut all = Vec::new();
    for page in 1..=2 {
        let url = format!(
            "https://packagist.org/search.json?q=&per_page=100&page={}",
            page
        );
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            break;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let results = body["results"].as_array()?;
        for pkg in results {
            if let Some(name) = pkg["name"].as_str() {
                all.push(name.to_string());
            }
        }
    }
    if all.is_empty() { None } else { Some(all) }
}

/// NuGet: search API includes downloadCount sorting
async fn fetch_nuget_popular(client: &reqwest::Client) -> Option<Vec<String>> {
    let mut all = Vec::new();
    for skip in [0, 100] {
        let url = format!(
            "https://azuresearch-usnc.nuget.org/query?q=&skip={}&take=100&semVerLevel=2",
            skip
        );
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            break;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let data = body["data"].as_array()?;
        for pkg in data {
            if let Some(id) = pkg["id"].as_str() {
                all.push(id.to_string());
            }
        }
    }
    if all.is_empty() { None } else { Some(all) }
}

/// Hardcoded fallback lists for ecosystems without good popularity APIs,
/// and as a safety net when API fetches fail.
fn fallback_popular(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &[
            "react", "express", "lodash", "axios", "webpack", "typescript", "next", "vue",
            "angular", "moment", "chalk", "commander", "debug", "uuid", "dotenv", "cors",
            "jsonwebtoken", "mongoose", "socket.io", "jest", "eslint", "prettier", "vite",
            "esbuild", "rollup", "babel-core", "tslib", "rxjs", "dayjs", "date-fns", "zod",
            "yup", "joi", "passport", "bcrypt", "helmet", "morgan", "winston", "pino",
            "fastify", "koa", "hapi", "inquirer", "yargs", "minimist", "glob", "rimraf",
            "mkdirp", "semver", "bluebird", "async", "underscore", "ramda", "immutable",
            "redux", "mobx", "zustand", "immer", "classnames", "tailwindcss", "postcss",
            "autoprefixer", "sass", "less", "styled-components", "emotion",
            "graphql", "apollo-server", "prisma", "sequelize", "knex", "typeorm",
            "cheerio", "puppeteer", "playwright", "cypress", "mocha", "chai", "sinon",
            "supertest", "nock", "nodemon", "pm2", "dotenv-expand", "cross-env",
            "husky", "lint-staged", "concurrently", "lerna", "nx", "turbo",
            "body-parser", "cookie-parser", "multer", "formidable", "busboy",
            "sharp", "jimp", "canvas", "pdf-lib", "xlsx", "csv-parse",
            "nodemailer", "twilio", "stripe", "aws-sdk", "firebase",
        ],
        "pypi" => &[
            "requests", "numpy", "pandas", "flask", "django", "pytest", "scipy",
            "matplotlib", "pillow", "sqlalchemy", "celery", "fastapi", "pydantic", "httpx",
            "uvicorn", "gunicorn", "boto3", "selenium", "scrapy", "beautifulsoup4",
            "click", "aiohttp", "cryptography", "jinja2", "werkzeug", "packaging",
            "setuptools", "wheel", "pip", "tqdm", "rich", "typer", "black", "ruff",
            "mypy", "flake8", "pylint", "isort", "bandit", "poetry", "pipenv",
            "tornado", "twisted", "gevent", "redis", "pymongo", "psycopg2",
            "marshmallow", "attrs", "dataclasses", "pyyaml", "toml", "orjson",
            "starlette", "sanic", "falcon", "bottle", "pyramid",
            "alembic", "peewee", "motor", "elasticsearch", "kafka-python",
            "paramiko", "fabric", "ansible", "docker", "kubernetes",
            "tensorflow", "torch", "keras", "scikit-learn", "xgboost",
            "networkx", "sympy", "statsmodels", "seaborn", "plotly",
            "openpyxl", "xlrd", "reportlab", "fpdf", "python-docx",
            "lxml", "chardet", "certifi", "urllib3", "idna",
        ],
        "cargo" => &[
            "serde", "tokio", "clap", "reqwest", "anyhow", "thiserror", "rand", "regex",
            "chrono", "hyper", "actix-web", "axum", "tracing", "log", "futures", "syn",
            "quote", "proc-macro2", "bytes", "tower", "serde_json", "once_cell",
            "lazy_static", "rayon", "itertools", "dashmap", "crossbeam", "parking_lot",
            "num", "uuid", "url", "http", "tonic", "prost", "sqlx", "diesel",
            "sea-orm", "rocket", "warp", "tide", "async-std", "smol",
            "mio", "libc", "nix", "winapi", "cc", "bindgen", "cmake",
            "serde_yaml", "toml", "config", "dotenv", "env_logger",
            "tracing-subscriber", "flexi_logger", "pretty_env_logger",
            "sha2", "hmac", "aes", "ring", "rustls", "native-tls",
            "image", "png", "gif", "zip", "tar", "flate2",
            "tempfile", "walkdir", "notify", "dirs", "home",
            "criterion", "proptest", "insta", "assert_cmd", "predicates",
            "strsim", "similar", "colored", "console", "indicatif",
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
            "github.com/aws/aws-sdk-go", "github.com/Azure/azure-sdk-for-go",
            "github.com/google/uuid", "github.com/grpc-ecosystem/grpc-gateway",
            "github.com/go-playground/validator", "github.com/swaggo/swag",
            "github.com/uber-go/fx", "github.com/tidwall/gjson",
            "github.com/go-sql-driver/mysql", "github.com/lib/pq",
            "github.com/olivere/elastic", "github.com/Shopify/sarama",
            "github.com/dgrijalva/jwt-go", "github.com/mitchellh/mapstructure",
            "github.com/pelletier/go-toml", "github.com/fsnotify/fsnotify",
            "github.com/cenkalti/backoff", "github.com/pkg/errors",
            "github.com/go-kit/kit", "github.com/micro/micro",
        ],
        "ruby" => &[
            "rails", "puma", "sidekiq", "devise", "rspec", "rubocop", "faker",
            "nokogiri", "pg", "redis", "rack", "sinatra", "capybara", "bcrypt",
            "aws-sdk", "activerecord", "bundler", "rspec-rails", "factory_bot",
            "webpacker", "turbo-rails", "stimulus-rails", "importmap-rails",
            "sprockets", "jbuilder", "sass-rails", "coffee-rails", "uglifier",
            "pundit", "cancancan", "omniauth", "doorkeeper", "warden",
            "carrierwave", "paperclip", "activestorage", "shrine",
            "resque", "delayed_job", "good_job", "que",
            "grape", "hanami", "dry-rb", "rom-rb",
            "minitest", "shoulda", "vcr", "webmock", "simplecov",
            "pry", "byebug", "better_errors", "bullet",
            "kaminari", "pagy", "will_paginate",
            "haml", "slim", "liquid", "erubi",
            "httparty", "faraday", "rest-client", "typhoeus",
            "whenever", "rufus-scheduler", "clockwork",
        ],
        "php" => &[
            "laravel/framework", "symfony/console", "guzzlehttp/guzzle",
            "phpunit/phpunit", "monolog/monolog", "doctrine/orm",
            "league/flysystem", "vlucas/phpdotenv", "predis/predis",
            "phpstan/phpstan", "symfony/http-foundation", "nikic/fast-route",
            "ramsey/uuid", "twig/twig", "carbon/carbon", "intervention/image",
            "spatie/laravel-permission", "filp/whoops", "mockery/mockery",
            "barryvdh/laravel-debugbar", "illuminate/support", "illuminate/database",
            "illuminate/http", "illuminate/routing", "illuminate/events",
            "symfony/yaml", "symfony/process", "symfony/finder",
            "symfony/http-kernel", "symfony/routing", "symfony/event-dispatcher",
            "psr/log", "psr/http-message", "psr/container", "psr/cache",
            "league/oauth2-client", "league/csv", "league/glide",
            "spatie/laravel-medialibrary", "spatie/laravel-backup",
            "livewire/livewire", "filament/filament",
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
            "org.springframework.boot:spring-boot-starter",
            "org.springframework:spring-context",
            "org.springframework:spring-web",
            "org.apache.commons:commons-io",
            "org.apache.commons:commons-collections4",
            "com.google.protobuf:protobuf-java",
            "io.projectreactor:reactor-core",
            "org.junit.jupiter:junit-jupiter",
            "org.testcontainers:testcontainers",
            "com.h2database:h2",
        ],
        "dotnet" => &[
            "Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection",
            "xunit", "Serilog", "AutoMapper", "MediatR", "FluentValidation",
            "Dapper", "Polly", "Moq", "Swashbuckle.AspNetCore",
            "StackExchange.Redis", "Microsoft.EntityFrameworkCore", "NUnit",
            "FluentAssertions", "Bogus", "Hangfire", "MassTransit",
            "Microsoft.Extensions.Logging", "Npgsql",
            "Microsoft.Extensions.Configuration",
            "Microsoft.Extensions.Http",
            "Microsoft.AspNetCore.Authentication.JwtBearer",
            "System.Text.Json", "Grpc.Net.Client",
            "AWSSDK.Core", "Azure.Identity", "MongoDB.Driver",
            "RabbitMQ.Client", "Confluent.Kafka",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_popular_returns_entries_for_all_ecosystems() {
        for eco in &["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"] {
            let packages = fallback_popular(eco);
            assert!(
                packages.len() >= 20,
                "{} has only {} fallback packages",
                eco,
                packages.len()
            );
        }
        assert!(fallback_popular("unknown").is_empty());
    }

    #[test]
    fn cache_round_trip() {
        let ecosystem = "test-corpus-rt";
        let packages = vec!["foo".to_string(), "bar".to_string()];
        save_cached(ecosystem, &packages);
        let loaded = load_cached(ecosystem);
        assert_eq!(loaded, Some(packages));

        // Clean up
        let _ = std::fs::remove_file(cache_path(ecosystem));
    }
}

use super::*;
use crate::config::SloppyJoeConfig;
use crate::registry::PackageMetadata;

/// Tagged mutations per dependency: dependency name -> candidate name -> generator name.
type Mutations = HashMap<String, HashMap<String, &'static str>>;

/// A registry existence probe: dependency name, candidate name, probe result.
type Probe = (String, String, std::result::Result<bool, anyhow::Error>);

struct Run<'a> {
    registry: &'a dyn Registry,
    deps: &'a [Dependency],
    ecosystem: Ecosystem,
    config: &'a SloppyJoeConfig,
    flagged: HashSet<String>,
    issues: Vec<Issue>,
}

/// Outcome of probing the registry for mutation candidates.
struct CandidateLookup {
    cached_matches: Vec<(String, String)>,
    fresh_results: Vec<Probe>,
    error_count: usize,
}

impl CandidateLookup {
    fn total_queries(&self) -> usize {
        self.fresh_results.len()
    }

    /// Candidates that exist on the registry, grouped by the dependency they imitate.
    fn into_matches(self) -> HashMap<String, Vec<String>> {
        let mut matches: HashMap<String, Vec<String>> = HashMap::new();
        for (dep_name, candidate) in self.cached_matches {
            matches.entry(dep_name).or_default().push(candidate);
        }
        for (dep_name, candidate, result) in self.fresh_results {
            if matches!(result, Ok(true)) {
                matches.entry(dep_name).or_default().push(candidate);
            }
        }
        matches
    }
}

fn registry_unreachable_issue(error_count: usize, total_queries: usize) -> Issue {
    let error_rate = error_count as f64 / total_queries.max(1) as f64;
    Issue::new(
        "<registry>",
        crate::names::SIMILARITY_REGISTRY_UNREACHABLE,
        Severity::Error,
    )
    .message(format!(
        "Registry queries failed for {} of {} similarity checks ({:.0}%). \
         Similarity detection is unreliable. Fix network connectivity or retry.",
        error_count,
        total_queries,
        error_rate * 100.0
    ))
    .fix("Ensure the registry is reachable. Use --no-cache to bypass stale cache data.")
}

/// Download counts of the original dependencies, for disparity evidence.
fn download_counts(
    dep_metadata: Option<&[crate::checks::metadata::MetadataLookup]>,
) -> HashMap<String, u64> {
    dep_metadata
        .map(|lookups| {
            lookups
                .iter()
                .filter_map(|lookup| {
                    Some((lookup.package.clone(), lookup.metadata.as_ref()?.downloads?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Record `candidate` as a `generator` mutation unless a stronger generator already found it.
fn add_tagged(
    mutations: &mut HashMap<String, &'static str>,
    candidate: String,
    generator: &'static str,
) {
    mutations
        .entry(candidate)
        .and_modify(|existing| {
            if generator_severity(generator) > generator_severity(existing) {
                *existing = generator;
            }
        })
        .or_insert(generator);
}

/// Evidence about the lookalike's popularity and age, appended to a similarity finding.
fn match_evidence(
    dep_name: &str,
    candidate: &str,
    meta: &PackageMetadata,
    dep_downloads: Option<u64>,
) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(downloads) = meta.downloads {
        parts.push(format!("{} has {} downloads", candidate, downloads));
    }
    if let Some(ref created) = meta.created {
        parts.push(format!("was first published {}", created));
    }
    if let Some(note) = download_disparity_note(dep_name, dep_downloads, candidate, meta.downloads)
    {
        parts.push(note);
    }
    parts
}

fn match_issue(
    dep_name: &str,
    candidate: &str,
    generator: &str,
    metadata: Option<&PackageMetadata>,
    dep_downloads: Option<u64>,
) -> Issue {
    let mut message = format_match_message(dep_name, candidate, generator);
    let evidence = metadata
        .map(|meta| match_evidence(dep_name, candidate, meta, dep_downloads))
        .unwrap_or_default();
    if !evidence.is_empty() {
        message = format!("{} ({})", message, evidence.join("; "));
    }
    make_issue(
        dep_name,
        candidate,
        generator,
        &message,
        "Examine both packages and add the intended one to your allowed list.",
    )
}

impl<'a> Run<'a> {
    /// Every name is expanded into thousands of registry probes, so absurdly long names
    /// would multiply requests. Skipping them silently would be a gap, so they block.
    fn flag_oversized_names(&mut self) {
        for dep in self.deps {
            if dep.package_name().chars().count() > MAX_SIMILARITY_NAME_CHARS
                && self.flagged.insert(dep.package_name().to_string())
            {
                self.issues.push(
                    Issue::new(
                        dep.package_name().chars().take(64).collect::<String>() + "...",
                        crate::names::SIMILARITY_NAME_TOO_LONG,
                        Severity::Error,
                    )
                    .message(format!(
                        "Package name is longer than {MAX_SIMILARITY_NAME_CHARS} characters, so its lookalike variants cannot be checked without an unbounded number of registry requests."
                    ))
                    .fix("Verify the dependency manually and replace it with a package that has a conventional name."),
                );
            }
        }
    }

    // ---- Phase 0: Scope squatting (no registry needed) ----
    fn check_scope_squatting(&mut self) {
        let configured_scopes = self.config.trusted_scopes(self.ecosystem.as_str());
        for dep in self.deps {
            let Some(issue) = self.scope_squatting_issue(dep, &configured_scopes) else {
                continue;
            };
            if self.flagged.insert(dep.package_name().to_string()) {
                self.issues.push(issue);
            }
        }
    }

    fn scope_squatting_issue(
        &self,
        dep: &Dependency,
        configured_scopes: &[String],
    ) -> Option<Issue> {
        let scope = extract_scope(dep.package_name(), self.ecosystem)?;
        let scope_lower = scope.to_lowercase();
        let all_known = || {
            known_scopes(self.ecosystem)
                .iter()
                .copied()
                .chain(configured_scopes.iter().map(String::as_str))
        };
        // Exact match to any known scope is safe -- check the whole list
        // first, since a real scope (e.g. @auth0) can be a near-match of
        // another real scope listed earlier (@auth).
        if all_known().any(|known| known.to_lowercase() == scope_lower) {
            return None;
        }
        let threshold = max_distance(scope_lower.len());
        for known in all_known() {
            let distance = strsim::levenshtein(&scope_lower, &known.to_lowercase());
            if distance == 0 || distance > threshold {
                continue;
            }
            let candidate = dep.package_name().replace(&scope, known);
            if is_suppressed(
                self.config,
                self.ecosystem,
                dep.package_name(),
                &candidate,
                "scope-squatting",
            ) {
                continue;
            }
            return Some(make_issue(
                dep.package_name(),
                &candidate,
                "scope-squatting",
                &format!(
                    "Scope '{}' is {} character{} away from the known scope '{}'.\n      \
                     Scope squatting is a known supply chain attack vector.",
                    scope,
                    distance,
                    if distance == 1 { "" } else { "s" },
                    known
                ),
                &format!(
                    "If you meant '{}', fix the scope in your manifest.",
                    candidate
                ),
            ));
        }
        None
    }

    /// Tagged mutations of every dependency not already flagged, computed once for phases 1 and 2.
    fn mutations(&self, paranoid: bool) -> Mutations {
        let generators = if paranoid {
            generators::paranoid_generators()
        } else {
            generators::default_generators()
        };
        let configured_roots = self.config.similarity_roots(self.ecosystem.as_str());
        let mut all_mutations = Mutations::new();
        for dep in self.deps {
            if self.flagged.contains(dep.package_name()) {
                continue;
            }
            let mut mutations =
                generate_mutations_with(&generators, dep.package_name(), self.ecosystem);
            for candidate in generators::segment_overlap_variants_with_additional_roots(
                dep.package_name(),
                self.ecosystem,
                &configured_roots,
            ) {
                add_tagged(&mut mutations, candidate, "segment-overlap");
            }
            for candidate in generators::missing_char_targets(
                dep.package_name(),
                self.ecosystem,
                &configured_roots,
            ) {
                add_tagged(&mut mutations, candidate, "missing-char");
            }
            if self.ecosystem == Ecosystem::Cargo {
                let identity = dep.package_name().replace('-', "_");
                mutations.retain(|candidate, _| {
                    !candidate.replace('-', "_").eq_ignore_ascii_case(&identity)
                });
            }
            mutations.retain(|candidate, _| {
                crate::ecosystem::validate_package_name_for_ecosystem(candidate, self.ecosystem)
            });
            all_mutations.insert(dep.package_name().to_string(), mutations);
        }
        all_mutations
    }

    // ---- Phase 1: Intra-manifest comparison (no network) ----
    fn compare_within_manifest(&mut self, all_mutations: &Mutations) {
        let dep_names: HashSet<String> = self
            .deps
            .iter()
            .map(|d| d.package_name().to_lowercase())
            .collect();
        for dep in self.deps {
            if self.flagged.contains(dep.package_name()) {
                continue;
            }
            let Some(mutations) = all_mutations.get(dep.package_name()) else {
                continue;
            };
            let collision = mutations.iter().find_map(|(mutation, gen_name)| {
                let mutation_lower = mutation.to_lowercase();
                let suppressed = is_suppressed(
                    self.config,
                    self.ecosystem,
                    dep.package_name(),
                    &mutation_lower,
                    gen_name,
                );
                let collides = dep_names.contains(&mutation_lower)
                    && mutation_lower != dep.package_name().to_lowercase();
                (!suppressed && collides).then_some((mutation_lower, *gen_name))
            });
            let Some((mutation_lower, gen_name)) = collision else {
                continue;
            };
            if self.flagged.insert(dep.package_name().to_string()) {
                let message = format_match_message(dep.package_name(), &mutation_lower, gen_name);
                self.issues.push(make_issue(
                    dep.package_name(),
                    &mutation_lower,
                    gen_name,
                    &format!(
                        "{} Both '{}' and '{}' are in your manifest.",
                        message,
                        dep.package_name(),
                        mutation_lower
                    ),
                    "Examine both packages and add the intended one to your allowed list.",
                ));
            }
        }
    }

    // ---- Phase 2: Batch-query registry for non-flagged deps ----
    fn candidate_queries(&self, all_mutations: &Mutations) -> Vec<(String, String)> {
        let mut queries = Vec::new();
        for dep in self.deps {
            if self.flagged.contains(dep.package_name()) {
                continue;
            }
            if let Some(mutations) = all_mutations.get(dep.package_name()) {
                for mutation in mutations.keys() {
                    queries.push((dep.package_name().to_string(), mutation.clone()));
                }
            }
        }
        queries
    }

    /// Probe the registry for each candidate, using and refreshing the 7-day disk cache
    /// (shared cache utilities: symlink protection, atomic writes).
    async fn lookup_candidates(
        &self,
        queries: Vec<(String, String)>,
        cache_dir: Option<&Path>,
        no_cache: bool,
    ) -> CandidateLookup {
        let cp = cache_path_for(self.ecosystem, cache_dir);
        let mut cache = if no_cache {
            SimilarityCache::default()
        } else {
            cache::read_json_cache(&cp, SIMILARITY_CACHE_TTL_SECS, |c: &SimilarityCache| {
                c.timestamp
            })
            .map(|c| c.normalize_and_expire(cache::now_epoch(), SIMILARITY_CACHE_TTL_SECS))
            .unwrap_or_default()
        };

        // Split queries into cached and uncached
        let mut cached_matches = Vec::new();
        let mut uncached = Vec::new();
        for (dep_name, candidate) in queries {
            match cache.get(&candidate) {
                Some(true) => cached_matches.push((dep_name, candidate)),
                Some(false) => {}
                None => uncached.push((dep_name, candidate)),
            }
        }

        // Batch-query registry for uncached candidates only
        let registry = self.registry;
        let fresh_results: Vec<Probe> = stream::iter(uncached)
            .map(|(dep_name, candidate)| async move {
                let result = registry.exists(&candidate).await;
                (dep_name, candidate, result)
            })
            .buffer_unordered(self.ecosystem.similarity_concurrency())
            .collect()
            .await;

        // Update cache with fresh results (only cache successes)
        let checked_at = cache::now_epoch();
        let mut error_count = 0usize;
        for (_, candidate, result) in &fresh_results {
            match result {
                Ok(exists) => {
                    cache.entries.insert(
                        candidate.clone(),
                        SimilarityCacheEntry::Timed {
                            exists: *exists,
                            checked_at,
                        },
                    );
                }
                Err(_) => error_count += 1,
            }
        }
        if !no_cache && !fresh_results.is_empty() {
            cache.timestamp = cache::now_epoch();
            cache::atomic_write_json(&cp, &cache);
        }

        CandidateLookup {
            cached_matches,
            fresh_results,
            error_count,
        }
    }

    // ---- Phase 3: Fetch metadata for matches concurrently, build issues ----
    /// For each dep with matches, the unsuppressed candidate with the highest generator severity.
    fn best_matches(
        &self,
        all_mutations: &Mutations,
        matches: &HashMap<String, Vec<String>>,
    ) -> Vec<(String, String)> {
        self.deps
            .iter()
            .filter(|dep| !self.flagged.contains(dep.package_name()))
            .filter_map(|dep| {
                let dep_matches = matches.get(dep.package_name())?;
                let dep_mutations = all_mutations.get(dep.package_name())?;
                let best = dep_matches
                    .iter()
                    .filter(|candidate| {
                        let generator = dep_mutations
                            .get(candidate.as_str())
                            .copied()
                            .unwrap_or("mutation-match");
                        !is_suppressed(
                            self.config,
                            self.ecosystem,
                            dep.package_name(),
                            candidate,
                            generator,
                        )
                    })
                    .max_by_key(|c| {
                        dep_mutations
                            .get(c.as_str())
                            .map(|g| generator_severity(g))
                            .unwrap_or(0)
                    })?;
                Some((dep.package_name().to_string(), best.clone()))
            })
            .collect()
    }

    async fn report_matches(
        &mut self,
        all_mutations: &Mutations,
        matches: HashMap<String, Vec<String>>,
        dep_downloads: &HashMap<String, u64>,
    ) {
        let metadata_queries = self.best_matches(all_mutations, &matches);
        let registry = self.registry;
        let metadata_results: Vec<(String, String, Option<PackageMetadata>)> =
            stream::iter(metadata_queries)
                .map(|(dep_name, candidate)| async move {
                    let meta = registry.metadata(&candidate, None).await.ok().flatten();
                    (dep_name, candidate, meta)
                })
                .buffer_unordered(self.ecosystem.similarity_concurrency())
                .collect()
                .await;

        for (dep_name, candidate, metadata) in metadata_results {
            if !self.flagged.insert(dep_name.clone()) {
                continue;
            }
            // Look up the generator name from tagged mutations (deterministic classification)
            let gen_name = all_mutations
                .get(&dep_name)
                .and_then(|m| m.get(candidate.as_str()).copied())
                .unwrap_or("mutation-match");
            self.issues.push(match_issue(
                &dep_name,
                &candidate,
                gen_name,
                metadata.as_ref(),
                dep_downloads.get(&dep_name).copied(),
            ));
        }
    }

    // ---- Case variant check for case-sensitive registries ----
    async fn check_case_variants(&mut self) {
        let mut queries = 0usize;
        let mut errors = 0usize;
        for dep in self.deps {
            if self.flagged.contains(dep.package_name()) {
                continue;
            }
            // On case-sensitive registries, check if the lowercased name exists on registry
            let dep_lower = dep.package_name().to_lowercase();
            if dep_lower == dep.package_name() {
                continue;
            }
            queries += 1;
            let exists = match self.registry.exists(&dep_lower).await {
                Ok(exists) => exists,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };
            let suppressed = is_suppressed(
                self.config,
                self.ecosystem,
                dep.package_name(),
                &dep_lower,
                "case-variant",
            );
            if exists && !suppressed && self.flagged.insert(dep.package_name().to_string()) {
                self.issues.push(make_issue(
                    dep.package_name(),
                    &dep_lower,
                    "case-variant",
                    &format!(
                        "'{}' differs from '{}' only in letter casing. \
                         On case-sensitive registries ({}) these resolve to different packages. \
                         An attacker could register the case variant.",
                        dep.package_name(),
                        dep_lower,
                        self.ecosystem
                    ),
                    &format!("Use the exact casing '{}' in your manifest.", dep_lower),
                ));
            }
        }
        if crate::checks::has_query_errors(errors) {
            self.issues
                .push(registry_unreachable_issue(errors, queries));
        }
    }
}

pub(crate) async fn check_similarity_with_options(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
    options: SimilarityRunOptions<'_>,
) -> Result<Vec<Issue>> {
    for dep in deps {
        if !ecosystem.supports_package_name_length(dep.package_name()) {
            anyhow::bail!(
                "Scan not supported: oversized package name for {}",
                ecosystem
            );
        }
    }
    let SimilarityRunOptions {
        cache_dir,
        no_cache,
        paranoid,
        dep_metadata,
        config,
    } = options;
    let mut run = Run {
        registry,
        deps,
        ecosystem,
        config,
        flagged: HashSet::new(),
        issues: Vec::new(),
    };
    run.flag_oversized_names();
    run.check_scope_squatting();
    let all_mutations = run.mutations(paranoid);
    run.compare_within_manifest(&all_mutations);

    let queries = run.candidate_queries(&all_mutations);
    let lookup = run.lookup_candidates(queries, cache_dir, no_cache).await;
    // Fail closed when the registry is unreachable.
    if crate::checks::has_query_errors(lookup.error_count) {
        let issue = registry_unreachable_issue(lookup.error_count, lookup.total_queries());
        run.issues.push(issue);
        return Ok(run.issues);
    }

    let dep_downloads = download_counts(dep_metadata);
    run.report_matches(&all_mutations, lookup.into_matches(), &dep_downloads)
        .await;
    if !is_case_insensitive(ecosystem) {
        run.check_case_variants().await;
    }
    Ok(run.issues)
}

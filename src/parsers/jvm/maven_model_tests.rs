//! Versions Maven derives from properties, management sections, imported BOMs
//! and the parent chain. Parent and BOM POMs come from an in-memory source.

use super::*;
use crate::parsers::test_utils::*;
use std::sync::Mutex;

struct FakeSource {
    poms: HashMap<(String, String, String), String>,
    fetched: Mutex<Vec<String>>,
}

impl FakeSource {
    fn new(poms: &[(&str, &str, &str, &str)]) -> Self {
        Self {
            poms: poms
                .iter()
                .map(|(g, a, v, body)| {
                    (
                        (g.to_string(), a.to_string(), v.to_string()),
                        body.to_string(),
                    )
                })
                .collect(),
            fetched: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl PomSource for FakeSource {
    async fn fetch(&self, c: &Coordinate) -> Result<String> {
        self.fetched
            .lock()
            .unwrap()
            .push(format!("{}:{}:{}", c.group, c.artifact, c.version));
        self.poms
            .get(&(c.group.clone(), c.artifact.clone(), c.version.clone()))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("POM {}:{}:{} not found", c.group, c.artifact, c.version)
            })
    }
}

fn pom(parent: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>demo</groupId><artifactId>app</artifactId><version>1.0</version>{body}</project>"
    )
}

fn parent_ref(g: &str, a: &str, v: &str) -> String {
    format!(
        "<parent><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version><relativePath/></parent>"
    )
}

async fn resolve(content: &str, source: &FakeSource) -> Result<Vec<(String, Option<String>)>> {
    let dir = setup_test_dir("jvm-model", "pom.xml", content);
    let path = dir.join("pom.xml");
    let deps = parse_pom(&path)?;
    let result = resolve_pom_versions(&path, deps, source).await;
    cleanup(&dir);
    Ok(result?.into_iter().map(|d| (d.name, d.version)).collect())
}

fn version_of(resolved: &[(String, Option<String>)], name: &str) -> Option<String> {
    resolved
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} missing from {resolved:?}"))
        .1
        .clone()
}

const DEP: &str = "<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>";

#[tokio::test]
async fn local_properties_are_interpolated() {
    let content = pom(
        "",
        &format!(
            "<properties><guava.version>31.1-jre</guava.version></properties><dependencies>{DEP}<version>${{guava.version}}</version></dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    assert_eq!(
        version_of(&resolved, "com.google.guava:guava").as_deref(),
        Some("31.1-jre")
    );
}

#[tokio::test]
async fn undefined_properties_leave_the_version_unset() {
    for reference in ["${missing.version}", "${env.GUAVA}", "${unterminated"] {
        let content = pom(
            "",
            &format!(
                "<dependencies>{DEP}<version>{reference}</version></dependency></dependencies>"
            ),
        );
        let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
        assert_eq!(
            version_of(&resolved, "com.google.guava:guava"),
            None,
            "{reference}"
        );
    }
}

#[tokio::test]
async fn builtin_project_properties_are_available() {
    let content = pom(
        "",
        &format!(
            "<dependencies>{DEP}<version>${{project.version}}</version></dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    assert_eq!(
        version_of(&resolved, "com.google.guava:guava").as_deref(),
        Some("1.0")
    );
}

#[tokio::test]
async fn local_dependency_management_supplies_missing_versions() {
    let content = pom(
        "",
        &format!(
            "<dependencyManagement><dependencies>{DEP}<version>31.1-jre</version></dependency></dependencies></dependencyManagement><dependencies>{DEP}</dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    assert!(
        resolved
            .iter()
            .all(|(_, v)| v.as_deref() == Some("31.1-jre")),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn explicit_versions_beat_management() {
    let content = pom(
        "",
        &format!(
            "<dependencyManagement><dependencies>{DEP}<version>31.1-jre</version></dependency></dependencies></dependencyManagement><dependencies>{DEP}<version>32.0.0-jre</version></dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    let versions: Vec<_> = resolved
        .iter()
        .filter(|(n, _)| n == "com.google.guava:guava")
        .collect();
    assert!(
        versions
            .iter()
            .any(|(_, v)| v.as_deref() == Some("32.0.0-jre"))
    );
}

const PARENT: &str = r#"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>parent</artifactId><version>7</version>
<properties><javadoc.version>3.6.3</javadoc.version><guava.version>30.0-jre</guava.version></properties>
<dependencyManagement><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency></dependencies></dependencyManagement>
<build><pluginManagement><plugins><plugin><artifactId>maven-javadoc-plugin</artifactId><version>${javadoc.version}</version></plugin></plugins></pluginManagement></build>
</project>"#;

#[tokio::test]
async fn parent_chain_supplies_plugin_and_dependency_versions() {
    let source = FakeSource::new(&[("org.example", "parent", "7", PARENT)]);
    let content = pom(
        &parent_ref("org.example", "parent", "7"),
        &format!(
            "<dependencies>{DEP}</dependency></dependencies><build><plugins><plugin><artifactId>maven-javadoc-plugin</artifactId></plugin></plugins></build>"
        ),
    );
    let resolved = resolve(&content, &source).await.unwrap();
    assert_eq!(
        version_of(&resolved, "com.google.guava:guava").as_deref(),
        Some("30.0-jre")
    );
    assert_eq!(
        version_of(&resolved, "org.apache.maven.plugins:maven-javadoc-plugin").as_deref(),
        Some("3.6.3")
    );
    // The parent coordinate itself keeps its literal version.
    assert_eq!(
        version_of(&resolved, "org.example:parent").as_deref(),
        Some("7")
    );
}

#[tokio::test]
async fn child_properties_override_parent_properties() {
    let source = FakeSource::new(&[("org.example", "parent", "7", PARENT)]);
    let content = pom(
        &parent_ref("org.example", "parent", "7"),
        &format!(
            "<properties><guava.version>33.0.0-jre</guava.version></properties><dependencies>{DEP}</dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &source).await.unwrap();
    assert_eq!(
        version_of(&resolved, "com.google.guava:guava").as_deref(),
        Some("33.0.0-jre")
    );
}

const BOM: &str = r#"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>bom</artifactId><version>2</version>
<properties><slf4j.version>2.0.9</slf4j.version></properties>
<dependencyManagement><dependencies>
<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>${slf4j.version}</version></dependency>
<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>29.0-jre</version></dependency>
</dependencies></dependencyManagement></project>"#;

#[tokio::test]
async fn imported_bom_supplies_versions_but_local_management_wins() {
    let source = FakeSource::new(&[("org.example", "bom", "2", BOM)]);
    let content = pom(
        "",
        &format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>2</version><type>pom</type><scope>import</scope></dependency>{DEP}<version>31.1-jre</version></dependency></dependencies></dependencyManagement><dependencies>{DEP}</dependency><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &source).await.unwrap();
    let guava: Vec<_> = resolved
        .iter()
        .filter(|(n, _)| n == "com.google.guava:guava")
        .collect();
    assert!(
        guava.iter().all(|(_, v)| v.as_deref() == Some("31.1-jre")),
        "{guava:?}"
    );
    assert_eq!(
        version_of(&resolved, "org.slf4j:slf4j-api").as_deref(),
        Some("2.0.9")
    );
}

#[tokio::test]
async fn conflicting_management_entries_leave_the_version_unset() {
    let content = pom(
        "",
        &format!(
            "<dependencyManagement><dependencies>{DEP}<version>1.0</version></dependency>{DEP}<version>2.0</version></dependency></dependencies></dependencyManagement><dependencies>{DEP}</dependency></dependencies>"
        ),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    let versions: Vec<_> = resolved
        .iter()
        .filter(|(n, v)| {
            n == "com.google.guava:guava"
                && v.as_deref() != Some("1.0")
                && v.as_deref() != Some("2.0")
        })
        .collect();
    assert!(
        !versions.is_empty(),
        "the versionless declaration must stay unresolved: {resolved:?}"
    );
}

#[tokio::test]
async fn unavailable_parent_poms_fail_closed() {
    let content = pom(&parent_ref("org.example", "gone", "1"), "");
    assert!(resolve(&content, &FakeSource::new(&[])).await.is_err());
}

#[tokio::test]
async fn property_parent_versions_leave_managed_versions_unset() {
    let content = pom(
        &parent_ref("org.example", "parent", "${revision}"),
        &format!("<dependencies>{DEP}</dependency></dependencies>"),
    );
    let source = FakeSource::new(&[]);
    let resolved = resolve(&content, &source).await.unwrap();
    assert_eq!(version_of(&resolved, "com.google.guava:guava"), None);
    assert!(
        source.fetched.lock().unwrap().is_empty(),
        "no fetch with an unresolved version"
    );
}

#[tokio::test]
async fn endless_parent_chains_are_rejected() {
    // A POM whose parent is itself.
    let looping = r#"<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId><artifactId>loop</artifactId><version>1</version><relativePath/></parent></project>"#;
    let source = FakeSource::new(&[("org.example", "loop", "1", looping)]);
    let content = pom(&parent_ref("org.example", "loop", "1"), "");
    assert!(resolve(&content, &source).await.is_err());
}

// ── Differentials found by the round-5 red team ─────────────────────────

#[test]
fn exclusion_versions_never_shadow_the_dependency_version() {
    let dir = setup_test_dir(
        "jvm-model-exclusion",
        "pom.xml",
        &pom("", &format!("<dependencies>{DEP}<exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId><version>9.9</version></exclusion></exclusions><version>3.2.1</version></dependency></dependencies>")),
    );
    let deps = parse_pom(&dir.join("pom.xml")).unwrap();
    cleanup(&dir);
    let guava = deps.iter().find(|d| d.name == "com.google.guava:guava").unwrap();
    assert_eq!(guava.version.as_deref(), Some("3.2.1"));
}

#[test]
fn exclusions_listed_first_never_rename_the_dependency() {
    let dir = setup_test_dir(
        "jvm-model-exclusion-first",
        "pom.xml",
        &pom("", "<dependencies><dependency><exclusions><exclusion><groupId>decoy</groupId><artifactId>decoy</artifactId></exclusion></exclusions><groupId>real</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>"),
    );
    let deps = parse_pom(&dir.join("pom.xml")).unwrap();
    cleanup(&dir);
    assert!(deps.iter().any(|d| d.name == "real:lib"), "{deps:?}");
    assert!(!deps.iter().any(|d| d.name == "decoy:decoy"), "{deps:?}");
}

#[tokio::test]
async fn commented_out_xml_is_ignored() {
    let body = format!(
        "<!-- <project><properties><guava.version>3.2.2</guava.version></properties></project> -->{}",
        pom("", &format!("<properties><guava.version>3.2.1</guava.version></properties><dependencies>{DEP}<version>${{guava.version}}</version></dependency></dependencies>"))
    );
    let resolved = resolve(&body, &FakeSource::new(&[])).await.unwrap();
    assert_eq!(version_of(&resolved, "com.google.guava:guava").as_deref(), Some("3.2.1"));
}

#[tokio::test]
async fn duplicate_sections_block_instead_of_picking_one() {
    for section in [
        "<properties><guava.version>1</guava.version></properties><properties><guava.version>2</guava.version></properties>",
        "<dependencies/><dependencies/>",
        "<build/><build/>",
    ] {
        let content = pom("", section);
        assert!(resolve(&content, &FakeSource::new(&[])).await.is_err(), "{section}");
    }
}

#[tokio::test]
async fn profile_properties_that_differ_leave_the_version_unset() {
    let content = pom(
        "",
        &format!("<properties><guava.version>3.2.2</guava.version></properties><profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><properties><guava.version>3.2.1</guava.version></properties></profile></profiles><dependencies>{DEP}<version>${{guava.version}}</version></dependency></dependencies>"),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    assert_eq!(version_of(&resolved, "com.google.guava:guava"), None);
}

#[tokio::test]
async fn profile_properties_that_agree_are_harmless() {
    let content = pom(
        "",
        &format!("<properties><guava.version>3.2.2</guava.version></properties><profiles><profile><id>p</id><properties><guava.version>3.2.2</guava.version></properties></profile></profiles><dependencies>{DEP}<version>${{guava.version}}</version></dependency></dependencies>"),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    assert_eq!(version_of(&resolved, "com.google.guava:guava").as_deref(), Some("3.2.2"));
}

#[tokio::test]
async fn profile_management_that_differs_leaves_the_version_unset() {
    let content = pom(
        "",
        &format!("<dependencyManagement><dependencies>{DEP}<version>3.2.2</version></dependency></dependencies></dependencyManagement><profiles><profile><id>p</id><dependencyManagement><dependencies>{DEP}<version>3.2.1</version></dependency></dependencies></dependencyManagement></profile></profiles><dependencies>{DEP}</dependency></dependencies>"),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    let unmanaged: Vec<_> = resolved
        .iter()
        .filter(|(n, v)| n == "com.google.guava:guava" && v.is_none())
        .collect();
    assert!(!unmanaged.is_empty(), "{resolved:?}");
}

#[tokio::test]
async fn maven_config_defines_leave_the_property_unset() {
    let dir = setup_test_dir(
        "jvm-model-mvnconfig",
        "pom.xml",
        &pom("", &format!("<properties><guava.version>3.2.2</guava.version></properties><dependencies>{DEP}<version>${{guava.version}}</version></dependency></dependencies>")),
    );
    std::fs::create_dir_all(dir.join(".mvn")).unwrap();
    std::fs::write(dir.join(".mvn/maven.config"), "-Dguava.version=3.2.1\n-B\n").unwrap();
    let path = dir.join("pom.xml");
    let deps = parse_pom(&path).unwrap();
    let resolved = resolve_pom_versions(&path, deps, &FakeSource::new(&[])).await.unwrap();
    cleanup(&dir);
    let guava = resolved.iter().find(|d| d.name == "com.google.guava:guava").unwrap();
    assert_eq!(guava.version, None);
}

#[tokio::test]
async fn inherited_dependencies_of_a_local_parent_are_scanned() {
    let dir = setup_test_dir(
        "jvm-model-inherited",
        "pom.xml",
        &pom(
            "<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>7</version><relativePath>parent.xml</relativePath></parent>",
            "",
        ),
    );
    std::fs::write(
        dir.join("parent.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>parent</artifactId><version>7</version><dependencies><dependency><groupId>commons-collections</groupId><artifactId>commons-collections</artifactId><version>3.2.1</version></dependency></dependencies><build><plugins><plugin><artifactId>maven-antrun-plugin</artifactId><version>3.1.0</version></plugin></plugins></build></project>",
    )
    .unwrap();
    let path = dir.join("pom.xml");
    let deps = parse_pom(&path).unwrap();
    let resolved = resolve_pom_versions(&path, deps, &FakeSource::new(&[])).await.unwrap();
    cleanup(&dir);
    let names: Vec<_> = resolved
        .iter()
        .map(|d| (d.name.as_str(), d.version.as_deref()))
        .collect();
    assert!(names.contains(&("commons-collections:commons-collections", Some("3.2.1"))), "{names:?}");
    assert!(names.contains(&("org.apache.maven.plugins:maven-antrun-plugin", Some("3.1.0"))), "{names:?}");
}

#[tokio::test]
async fn inherited_dependencies_of_a_remote_parent_are_scanned() {
    let parent = r#"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>parent</artifactId><version>7</version>
<properties><cc.version>3.2.1</cc.version></properties>
<dependencies><dependency><groupId>commons-collections</groupId><artifactId>commons-collections</artifactId><version>${cc.version}</version></dependency></dependencies></project>"#;
    let source = FakeSource::new(&[("org.example", "parent", "7", parent)]);
    let content = pom(&parent_ref("org.example", "parent", "7"), "");
    let resolved = resolve(&content, &source).await.unwrap();
    assert_eq!(
        version_of(&resolved, "commons-collections:commons-collections").as_deref(),
        Some("3.2.1")
    );
}

#[tokio::test]
async fn plugin_management_never_fills_a_dependency_and_vice_versa() {
    let content = pom(
        "",
        &format!("<build><pluginManagement><plugins><plugin><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>9.9</version></plugin></plugins></pluginManagement><plugins><plugin><artifactId>maven-javadoc-plugin</artifactId></plugin></plugins></build><dependencyManagement><dependencies><dependency><groupId>org.apache.maven.plugins</groupId><artifactId>maven-javadoc-plugin</artifactId><version>8.8</version></dependency></dependencies></dependencyManagement><dependencies>{DEP}</dependency></dependencies>"),
    );
    let resolved = resolve(&content, &FakeSource::new(&[])).await.unwrap();
    let guava_unmanaged = resolved
        .iter()
        .any(|(n, v)| n == "com.google.guava:guava" && v.is_none());
    assert!(guava_unmanaged, "a plugin entry must not version a dependency: {resolved:?}");
    let javadoc = resolved
        .iter()
        .find(|(n, v)| n == "org.apache.maven.plugins:maven-javadoc-plugin" && v.is_none());
    assert!(javadoc.is_some(), "a dependency entry must not version a plugin: {resolved:?}");
}

#[tokio::test]
async fn classifier_management_does_not_shadow_the_plain_entry() {
    let source = FakeSource::new(&[("org.example", "parent", "7", PARENT)]);
    let content = pom(
        &parent_ref("org.example", "parent", "7"),
        &format!("<dependencyManagement><dependencies>{DEP}<version>31.0</version><classifier>tests</classifier></dependency></dependencies></dependencyManagement><dependencies>{DEP}</dependency></dependencies>"),
    );
    let resolved = resolve(&content, &source).await.unwrap();
    let versions: Vec<_> = resolved
        .iter()
        .filter(|(n, _)| n == "com.google.guava:guava")
        .map(|(_, v)| v.clone())
        .collect();
    assert!(versions.contains(&Some("30.0-jre".to_string())), "inherited plain entry must apply: {versions:?}");
}

//! Gradle plugin repositories (Plugin Portal / Maven Central) client.

/// A repository Gradle consults for plugin marker artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginRepository {
    GradlePluginPortal,
    MavenCentral,
    /// A repository-controlled URL (`maven { url ... }`).
    Custom(String),
}

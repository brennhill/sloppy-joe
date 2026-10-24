//! JVM system properties that a repository-controlled file (`gradle.properties`, `.mvn/*.config`)
//! can set to change where Gradle or Maven fetch from, what they trust, or where they keep state.

/// Property name prefixes that redirect repositories, replace the trust store, route traffic
/// through a proxy, move the home or local repository, or point at a build cache.
const REDIRECTING_PREFIXES: &[&str] = &[
    "javax.net.ssl.",
    "http.proxy",
    "https.proxy",
    "http.nonProxyHosts",
    "https.nonProxyHosts",
    "socksProxy",
    "user.home",
    "java.home",
    "maven.repo.local",
    "maven.repo.central",
    "maven.home",
    "maven.ext.class.path",
    "maven.build.cache",
    "org.apache.maven.user-settings",
    "org.apache.maven.global-settings",
    "aether.connector.",
    "org.gradle.internal.plugins.portal.url.override",
];

/// Whether `name` (a system property name without `-D`) redirects fetching or trust.
pub(super) fn is_redirecting_system_property(name: &str) -> bool {
    let name = name.trim();
    REDIRECTING_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// The first redirecting `-Dname[=value]` token in a JVM argument string, if any.
pub(super) fn redirecting_jvm_arg(args: &str) -> Option<String> {
    args.split(|c: char| c.is_whitespace() || c == '\u{0c}')
        .filter_map(|token| token.strip_prefix("-D"))
        .map(|rest| rest.split('=').next().unwrap_or(rest))
        .find(|name| is_redirecting_system_property(name))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirecting_properties_are_recognized() {
        for name in [
            "javax.net.ssl.trustStore",
            "https.proxyHost",
            "http.nonProxyHosts",
            "user.home",
            "maven.repo.local",
            "org.gradle.internal.plugins.portal.url.override",
            "aether.connector.https.securityMode",
        ] {
            assert!(is_redirecting_system_property(name), "{name}");
        }
        assert!(!is_redirecting_system_property("file.encoding"));
        assert!(!is_redirecting_system_property("maven.test.skip"));
    }

    #[test]
    fn jvm_args_are_scanned_for_redirecting_properties() {
        assert_eq!(
            redirecting_jvm_arg("-Xmx1g -Djavax.net.ssl.trustStore=a.jks").as_deref(),
            Some("javax.net.ssl.trustStore")
        );
        assert_eq!(redirecting_jvm_arg("-Xmx1g -Dfile.encoding=UTF-8"), None);
    }
}

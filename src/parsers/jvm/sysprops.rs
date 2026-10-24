//! JVM system properties that a repository-controlled file (`gradle.properties`, `.mvn/*.config`)
//! can set to change where Gradle or Maven fetch from, what they trust, or where they keep state.
//! The list is a macro so each surface can prepend its own spelling (`-D`, `systemProp.`) and
//! append its own denied entries while sharing one source of truth.

/// Expands to a `&[&str]` of denied key prefixes: every redirecting system property behind the
/// literal prefix `$p`, followed by the extra literals. Redirecting properties are those that
/// redirect repositories, replace the trust store, route traffic through a proxy, move the home,
/// the user directory or the local repository, load a class loader, security provider
/// configuration or native library, or point at a build cache.
macro_rules! redirecting_props {
    ($p:literal; $($extra:literal),* $(,)?) => {
        &[
            concat!($p, "javax.net.ssl."),
            concat!($p, "http.proxy"),
            concat!($p, "https.proxy"),
            concat!($p, "http.nonProxyHosts"),
            concat!($p, "https.nonProxyHosts"),
            concat!($p, "https.protocols"),
            concat!($p, "jdk.tls."),
            concat!($p, "socksProxy"),
            concat!($p, "user.home"),
            concat!($p, "user.dir"),
            concat!($p, "java.home"),
            concat!($p, "java.class.path"),
            concat!($p, "java.library.path"),
            concat!($p, "java.security."),
            concat!($p, "java.system.class.loader"),
            concat!($p, "gradle.user.home"),
            concat!($p, "maven.repo.local"),
            concat!($p, "maven.repo.central"),
            concat!($p, "maven.home"),
            concat!($p, "maven.ext.class.path"),
            concat!($p, "maven.build.cache"),
            concat!($p, "org.apache.maven.user-settings"),
            concat!($p, "org.apache.maven.global-settings"),
            concat!($p, "aether.connector."),
            concat!($p, "org.gradle.internal.plugins.portal.url.override"),
            $($extra),*
        ]
    };
}
pub(super) use redirecting_props;

#[cfg(test)]
mod tests {
    #[test]
    fn the_macro_prefixes_every_property_and_appends_extras() {
        const LIST: &[&str] = redirecting_props!("-D"; "-javaagent");
        assert!(LIST.contains(&"-Djavax.net.ssl."));
        assert!(LIST.contains(&"-Dmaven.repo.local"));
        assert!(LIST.contains(&"-Dorg.gradle.internal.plugins.portal.url.override"));
        assert_eq!(LIST.last(), Some(&"-javaagent"));
        const GRADLE: &[&str] = redirecting_props!("systemProp."; );
        assert!(GRADLE.contains(&"systemProp.https.proxy"));
    }
}

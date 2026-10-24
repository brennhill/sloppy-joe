use super::*;
use crate::parsers::test_utils::*;

#[test]
fn accept_static_gem_options() {
    for body in [
        "gem 'bootsnap', require: false",
        "gem \"bootsnap\", \"1.18.4\", require: false",
        "gem 'bootsnap', '1.18.4', require: 'bootsnap/setup'",
        "gem 'bootsnap', group: :development",
        "gem 'bootsnap', '1.18.4', groups: [:development, :test], platforms: %i[mri windows]",
        "gem 'bootsnap', platforms: [:mri, :mingw], require: nil",
        "gem 'bootsnap', :require => false, :group => :test",
        "gem('bootsnap', '1.18.4', require: false)",
        "gem 'bootsnap', '1.18.4',\n  require: false,\n  platform: :ruby",
    ] {
        let dir = setup_test_dir("gemfile", "Gemfile", body);
        let deps = parse(&dir).unwrap_or_else(|err| panic!("{body}: {err}"));
        assert_eq!(deps.len(), 1, "{body}");
        assert_eq!(deps[0].name, "bootsnap");
        cleanup(&dir);
    }
}

#[test]
fn reject_dynamic_gem_options() {
    for body in [
        "gem 'bootsnap', require: ENV['X']",
        "gem 'bootsnap', install_if: -> { true }",
        "gem 'bootsnap', require: \"#{name}\"",
        "gem 'bootsnap', group: some_group",
        "gem 'bootsnap', require: false, 'extra'",
        "gem 'bootsnap', unknown_option: true",
    ] {
        let dir = setup_test_dir("gemfile", "Gemfile", body);
        assert!(parse(&dir).is_err(), "must fail closed: {body}");
        cleanup(&dir);
    }
}

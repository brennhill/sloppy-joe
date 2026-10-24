//! Repository files Composer reads beside a PHP project.

use crate::ecosystems::ambient::{AmbientInput as Row, Disposition::*, Scope::*};

pub(super) const AMBIENT: &[Row] = &[
    // Composer treats packages recorded in a vendor tree as installed and may skip fetching them,
    // so a committed vendor/composer/installed.json stands in for packages nobody scanned.
    Row::new(
        "vendor/composer/installed.json",
        ProjectDir,
        BlockedIfTracked(
            "a committed vendor tree can stand in for packages composer.lock never covered. Fix: remove vendor/ from the repository and add it to .gitignore.",
        ),
    ),
    Row::new(
        "auth.json",
        ProjectDir,
        Irrelevant(
            "holds credentials only; it cannot name a package source or change what is fetched",
        ),
    ),
];

//! Scan orchestration, split by concern. Everything here is re-exported to the crate root
//! so existing paths keep working.
mod baseline;
mod discovery;
mod fingerprint;
pub(crate) mod fix;
mod internal_source;
mod parse_inputs;
mod preflight;
mod private_npm;
mod scan;

pub(crate) use baseline::*;
pub(crate) use discovery::*;
pub(crate) use fingerprint::*;
pub(crate) use internal_source::*;
pub(crate) use parse_inputs::*;
pub(crate) use preflight::*;
pub(crate) use private_npm::*;
pub(crate) use scan::*;

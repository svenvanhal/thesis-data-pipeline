// No unsafe here!
#![forbid(unsafe_code)]

#[macro_use]
extern crate serde_prefix;

// Shared (structs) between binaries
pub mod shared_interface;
pub mod cli;

// Preprocessing
pub mod parse_log;
pub mod parse_dns;

// Feature Extraction
pub mod feature_extraction;


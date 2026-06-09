//! Day-1 secret providers. CLI-backed ones (pass/age/sops) are thin
//! [`crate::CliManifest`]s run through the [`crate::SecretBroker`] choke-point;
//! native ones (dotenv/env) read files / process env directly (no spawn).

pub mod age;
pub mod dotenv;
pub mod env;
pub mod pass;
pub mod sops;

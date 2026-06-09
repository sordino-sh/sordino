//! zlauder-secrets — host-side secret providers + the registration classifier.
//!
//! This crate turns provider-addressed [`SecretRef`]s (`pass:openai/key#password`,
//! `age:secrets.age`, `env:PGPASSWORD`, …) into `zlauder_engine::SecretValue`s that
//! the proxy hands to `MaskEngine::set_secret_rules`. It NEVER touches engine
//! internals. The only process spawn in the crate is the [`SecretBroker`]
//! choke-point (secrets ride stdout, env is scrubbed); adding a CLI backend is a
//! [`CliManifest`], not new resolver code. [`classify`] is the anti-over-masking
//! gate applied at registration.

mod broker_spawn;
mod classify;
mod cli;
mod error;
mod provider;
pub mod providers;
mod types;

pub use broker_spawn::SecretBroker;
pub use classify::{Eligibility, EligibleReason, SkipReason, classify};
pub use cli::{CliManifest, CliProvider};
pub use error::ProviderError;
pub use provider::{ProviderRegistry, SecretProvider};
pub use types::{Caps, Health, SecretRef};

use std::path::PathBuf;

/// Build a registry with every day-1 provider registered (pass/age/sops/dotenv/env).
/// `project_root` scopes CLI providers that need it (sops' `.sops.yaml`).
pub fn default_registry(project_root: Option<PathBuf>) -> ProviderRegistry {
    let mut reg = ProviderRegistry::new();
    reg.register(Box::new(providers::pass::provider(project_root.clone())));
    reg.register(Box::new(providers::age::provider(project_root.clone())));
    reg.register(Box::new(providers::sops::provider(project_root.clone())));
    reg.register(Box::new(providers::dotenv::DotenvProvider::new(
        project_root.clone(),
    )));
    reg.register(Box::new(providers::env::EnvProvider));
    reg
}

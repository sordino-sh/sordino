use async_trait::async_trait;
use sordino_engine::SecretValue;

use crate::error::ProviderError;
use crate::types::{Caps, Health, SecretRef};

/// A secret backend. Implementations resolve a [`SecretRef`] to a [`SecretValue`]
/// and never touch the engine's internals — they only produce values the proxy then
/// hands to `MaskEngine::set_secret_rules`.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// The `scheme:` this provider answers (`pass`, `age`, `sops`, `dotenv`, `env`…).
    fn scheme(&self) -> &str;
    fn capabilities(&self) -> Caps;
    async fn health(&self) -> Health;
    async fn resolve(&self, r: &SecretRef) -> Result<SecretValue, ProviderError>;
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<SecretRef>, ProviderError>;
}

/// Routes a [`SecretRef`] to the registered provider for its scheme. Built once at
/// proxy start and used by the resolve/readiness path.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Vec<Box<dyn SecretProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, p: Box<dyn SecretProvider>) -> &mut Self {
        self.providers.push(p);
        self
    }

    pub fn provider(&self, scheme: &str) -> Option<&dyn SecretProvider> {
        self.providers
            .iter()
            .map(|b| b.as_ref())
            .find(|p| p.scheme() == scheme)
    }

    pub async fn resolve(&self, r: &SecretRef) -> Result<SecretValue, ProviderError> {
        match self.provider(&r.scheme) {
            Some(p) => p.resolve(r).await,
            None => Err(ProviderError::Unsupported(format!(
                "no provider for scheme {:?}",
                r.scheme
            ))),
        }
    }

    pub async fn health(&self, scheme: &str) -> Option<Health> {
        match self.provider(scheme) {
            Some(p) => Some(p.health().await),
            None => None,
        }
    }

    pub fn schemes(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.scheme()).collect()
    }
}

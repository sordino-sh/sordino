use async_trait::async_trait;

use zlauder_engine::SecretValue;

use crate::{Caps, Health, ProviderError, SecretProvider, SecretRef};

/// Resolves secrets from the process environment.
///
/// A reference's `path` names the environment variable; `field` is not
/// supported and `list` is unavailable (env has no enumerable namespace).
pub struct EnvProvider;

#[async_trait]
impl SecretProvider for EnvProvider {
    fn scheme(&self) -> &str {
        "env"
    }

    fn capabilities(&self) -> Caps {
        Caps::default()
    }

    async fn health(&self) -> Health {
        Health::Ok
    }

    async fn resolve(&self, r: &SecretRef) -> Result<SecretValue, ProviderError> {
        if r.field.is_some() {
            return Err(ProviderError::Unsupported("env has no #field".into()));
        }
        match std::env::var(&r.path) {
            Ok(v) => Ok(SecretValue::new(v)),
            Err(_) => Err(ProviderError::NotFound),
        }
    }

    async fn list(&self, _prefix: Option<&str>) -> Result<Vec<SecretRef>, ProviderError> {
        Err(ProviderError::Unsupported("env list".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_ref(path: &str) -> SecretRef {
        SecretRef {
            scheme: "env".into(),
            path: path.into(),
            field: None,
            version: None,
        }
    }

    #[tokio::test]
    async fn resolves_set_var_and_rejects_missing_and_field() {
        let name = "ZLAUDER_SECRETS_ENV_TEST_VAR_X9Q7";
        // Edition 2024 requires `unsafe` for set/remove_var; this test is
        // single-threaded so the mutation is sound.
        unsafe {
            std::env::set_var(name, "topsecret");
        }

        let p = EnvProvider;

        // Present variable resolves to its value.
        let got = p.resolve(&env_ref(name)).await.expect("resolve set var");
        assert_eq!(got.expose(), "topsecret");

        // A `#field` selector is unsupported.
        let mut with_field = env_ref(name);
        with_field.field = Some("sub".into());
        assert!(matches!(
            p.resolve(&with_field).await,
            Err(ProviderError::Unsupported(_))
        ));

        unsafe {
            std::env::remove_var(name);
        }

        // After removal the variable is gone.
        assert!(matches!(
            p.resolve(&env_ref(name)).await,
            Err(ProviderError::NotFound)
        ));
    }
}

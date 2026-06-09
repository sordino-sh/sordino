//! ZDR (Zero-Data-Retention) trust-routing primitives.
//!
//! This is the **Trust** switch — the third of zlauder's three orthogonal switches
//! (Routing / Masking / Trust). It lets a user route a single conversation to an
//! endpoint they have *independently verified* as non-retaining (an Anthropic
//! Commercial-org ZDR key, a self-hosted llama.cpp/vLLM box, a Bedrock/Vertex
//! deployment, …) — swapping the upstream base URL and credentials on the fly.
//!
//! Two hard invariants the types here encode:
//!   - **Masking still fully applies.** Routing to a ZDR endpoint does NOT reveal
//!     values; tokens are still sent (deny-by-default). Selective reveal is a later
//!     expansion (EV-A), gated behind the Secrets/Broker gate that already landed
//!     (INV-14). This foundation is **routing-only**.
//!   - **The ZDR credential never persists.** It is sourced from an env var at
//!     startup and lives only in-process on [`crate::state::AppState`]; it is never
//!     serialized into the 0600 state file, the `GET /zlauder/config` snapshot, or
//!     the monitor. [`ZdrTarget`] is deliberately NOT `Serialize`, and its key has a
//!     redacting `Debug`.
//!
//! ToS guard: the ZDR credential MUST NOT be a subscription / OAuth token (using a
//! Pro/Max OAuth token in a third-party tool is an actively enforced Anthropic ToS
//! violation). [`resolve_targets`] rejects an OAuth-shaped credential at load.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::config::{ZdrSection, ZdrTargetSpec};

/// A resolved ZDR API credential, held in-process only. `Debug` redacts the value
/// so it can never leak into a log line, and it is intentionally not `Serialize`.
#[derive(Clone)]
pub struct ZdrKey(String);

impl ZdrKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for ZdrKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            write!(f, "ZdrKey(<none>)")
        } else {
            // Length only — never the bytes.
            write!(f, "ZdrKey(<redacted {} chars>)", self.0.len())
        }
    }
}

/// *What kind* of trust an endpoint has — deliberately **not** an ordered level
/// (the four bases are not comparable). The badge always reads "asserted,
/// unverified": the system cannot verify ZDR, only the user can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustBasis {
    /// Contractual ZDR (Anthropic Commercial-org key, OpenAI ZDR, Azure modified
    /// abuse monitoring, …). Sales-gated, enterprise.
    Contractual { provider: String, org_scoped: bool },
    /// Cloud architecture (Bedrock/Vertex don't retain by default, but are NOT
    /// covered by Anthropic's ZDR agreement — trust rests on the cloud + the
    /// customer not enabling invocation logging).
    ProviderArchitecture,
    /// Self-hosted on the user's own metal (llama.cpp / vLLM): the user is the
    /// trust anchor.
    SelfHosted,
    /// Attested TEE — reserved-inert (no attestation quote is wired yet), mirroring
    /// the engine's reserved `TokenClass::Guard`.
    AttestedTee,
}

impl TrustBasis {
    /// The projection the (future EV-A) clearance predicate will consume. In the
    /// routing-only foundation it is informational: a basis the user declared and
    /// verified is treated as ZDR-grade for *routing*. A bare `AttestedTee` is NOT
    /// vouched for because no attestation is wired — fail-closed by construction.
    pub fn is_zdr_grade(&self) -> bool {
        match self {
            TrustBasis::Contractual { .. }
            | TrustBasis::ProviderArchitecture
            | TrustBasis::SelfHosted => true,
            TrustBasis::AttestedTee => false,
        }
    }

    /// Parse the config string form. `contractual` without a provider defaults to a
    /// generic, org-scoped contractual basis (the common Anthropic-org case).
    fn parse(s: &str) -> Result<TrustBasis, String> {
        match s {
            "self_hosted" => Ok(TrustBasis::SelfHosted),
            "provider_architecture" => Ok(TrustBasis::ProviderArchitecture),
            "attested_tee" => Ok(TrustBasis::AttestedTee),
            "contractual" => Ok(TrustBasis::Contractual {
                provider: "unspecified".into(),
                org_scoped: true,
            }),
            other => Err(format!(
                "unknown trust_basis '{other}' (valid: contractual, provider_architecture, \
                 self_hosted, attested_tee)"
            )),
        }
    }

    /// Stable snake_case label for the value-free snapshot / CLI.
    pub fn label(&self) -> &'static str {
        match self {
            TrustBasis::Contractual { .. } => "contractual",
            TrustBasis::ProviderArchitecture => "provider_architecture",
            TrustBasis::SelfHosted => "self_hosted",
            TrustBasis::AttestedTee => "attested_tee",
        }
    }
}

/// A resolved ZDR routing destination. Holds the in-process credential, so it is
/// **never** `Serialize` and lives only on [`crate::state::AppState`]. Construct via
/// [`resolve_targets`].
#[derive(Clone, Debug)]
pub struct ZdrTarget {
    pub name: String,
    /// Upstream base, trailing slash trimmed (so `base_url + path` is well-formed).
    pub base_url: String,
    /// Host (+ port) portion of `base_url`, for the rewritten `Host` header.
    pub host: String,
    pub trust_basis: TrustBasis,
    /// The user's independent assertion that this endpoint is non-retaining. A
    /// target with `user_verified = false` is registered but cannot be *engaged*
    /// (the control endpoint refuses it) — truthful chrome, deny-by-default.
    pub user_verified: bool,
    /// Extra headers injected on every ZDR request to this target (e.g. a provider
    /// `anthropic-beta` flag). Config-sourced, non-secret.
    pub extra_headers: Vec<(String, String)>,
    /// The ZDR API credential (env-sourced; in-process only). Empty ⇒ no auth header
    /// is injected (a no-auth self-hosted box).
    key: ZdrKey,
}

impl ZdrTarget {
    pub fn key(&self) -> &ZdrKey {
        &self.key
    }

    /// Value-free view for the admin snapshot / CLI (never carries the key).
    pub fn view(&self) -> ZdrTargetView {
        ZdrTargetView {
            name: self.name.clone(),
            base_url: self.base_url.clone(),
            trust_basis: self.trust_basis.label(),
            user_verified: self.user_verified,
            has_key: !self.key.is_empty(),
        }
    }
}

/// Value-free view of a target for the admin snapshot / CLI. NEVER carries the key
/// (only whether one is present).
#[derive(Clone, Debug, Serialize)]
pub struct ZdrTargetView {
    pub name: String,
    pub base_url: String,
    pub trust_basis: &'static str,
    pub user_verified: bool,
    pub has_key: bool,
}

/// A conversation's pinned ZDR posture: the name of the target it routes to.
#[derive(Clone, Debug, Serialize)]
pub struct ZdrSelection {
    pub target: String,
}

/// The trust posture resolved **once at request entry** and carried by value
/// through mask → dispatch → unmask. Fail-closed; the resolution taxonomy lives in
/// [`crate::routes`].
#[derive(Clone)]
pub enum PinnedMode {
    /// No ZDR selection — today's masked Anthropic path (default upstream, verbatim
    /// client credentials).
    Normal,
    /// Route this request to a verified ZDR target (swap base URL + credential).
    Zdr(Arc<ZdrTarget>),
}

impl PinnedMode {
    pub fn is_zdr(&self) -> bool {
        matches!(self, PinnedMode::Zdr(_))
    }
    pub fn target(&self) -> Option<&ZdrTarget> {
        match self {
            PinnedMode::Zdr(t) => Some(t),
            PinnedMode::Normal => None,
        }
    }
}

/// Outcome of resolving the `[zdr]` config at startup: the registry + default + any
/// per-target load errors (logged by the caller). A failed target is simply not
/// registered, so a session that later selects it fails closed at selection time.
pub struct ResolvedZdr {
    pub targets: HashMap<String, Arc<ZdrTarget>>,
    pub default: Option<String>,
    pub errors: Vec<String>,
}

/// Resolve `[zdr]` specs into runtime targets, reading each credential from its env
/// var. Synchronous: env reads don't block (unlike the secrets provider CLIs).
pub fn resolve_targets(section: &ZdrSection) -> ResolvedZdr {
    let mut targets: HashMap<String, Arc<ZdrTarget>> = HashMap::new();
    let mut errors = Vec::new();
    for spec in &section.target {
        if targets.contains_key(&spec.name) {
            errors.push(format!("[zdr] duplicate target name '{}'", spec.name));
            continue;
        }
        match resolve_one(spec) {
            Ok(t) => {
                targets.insert(t.name.clone(), Arc::new(t));
            }
            Err(e) => errors.push(format!("[zdr] target '{}': {e}", spec.name)),
        }
    }
    // A `default` naming an unresolved/absent target is dropped (with an error) so
    // `/zlauder:zdr` with no arg can never silently engage nothing.
    let default = section.default.clone().filter(|d| {
        let ok = targets.contains_key(d);
        if !ok {
            errors.push(format!("[zdr] default '{d}' names no resolved target"));
        }
        ok
    });
    ResolvedZdr {
        targets,
        default,
        errors,
    }
}

fn resolve_one(spec: &ZdrTargetSpec) -> Result<ZdrTarget, String> {
    if spec.name.trim().is_empty() {
        return Err("empty name".into());
    }
    let trust_basis = match spec.trust_basis.as_deref() {
        Some(s) => TrustBasis::parse(s)?,
        // Most conservative default: no declared basis ⇒ you are the anchor.
        None => TrustBasis::SelfHosted,
    };
    // Resolve the credential from its env var (refs-only; never inline — enforced by
    // the config scope invariant). Unset ⇒ no key (allowed for a no-auth self-hosted
    // box); present-but-OAuth-shaped ⇒ a hard ToS rejection.
    let key = match spec.from_env.as_deref() {
        Some(var) => match std::env::var(var) {
            Ok(v) => ZdrKey(v.trim().to_string()),
            Err(_) => ZdrKey(String::new()),
        },
        None => ZdrKey(String::new()),
    };
    reject_subscription_shaped(key.as_str())?;
    let host = host_of(&spec.base_url)?;
    Ok(ZdrTarget {
        name: spec.name.clone(),
        base_url: spec.base_url.trim().trim_end_matches('/').to_string(),
        host,
        trust_basis,
        user_verified: spec.user_verified,
        extra_headers: spec
            .extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        key,
    })
}

/// ToS guard: a ZDR credential must not be a subscription / OAuth token. Anthropic
/// OAuth access tokens (issued to Pro/Max subscriptions and used by Claude Code) are
/// `sk-ant-oat…`-shaped; a real Commercial **API key** is `sk-ant-api…`. We reject
/// the OAuth shape (and a bare `Bearer …` paste). This cannot *prove* a key is
/// contractual ZDR — only the user can — but it makes the one mechanically
/// detectable ToS violation a hard load error rather than a silent egress of a
/// subscription token to a third-party endpoint.
fn reject_subscription_shaped(key: &str) -> Result<(), String> {
    let k = key.trim();
    if k.is_empty() {
        return Ok(());
    }
    let lower = k.to_ascii_lowercase();
    if lower.starts_with("sk-ant-oat") || lower.starts_with("bearer ") || lower.starts_with("oauth")
    {
        return Err("credential looks like a subscription / OAuth token (sk-ant-oat… / Bearer …). \
                    A ZDR key MUST be a non-subscription API key — using an OAuth subscription \
                    token in a third-party tool violates Anthropic's ToS. Refusing to register \
                    this target."
            .into());
    }
    Ok(())
}

/// Host (+ port) portion of a base URL, for the rewritten `Host` header. Mirrors
/// `AppState::upstream_host`'s parsing so we add no `url` dependency.
fn host_of(base: &str) -> Result<String, String> {
    let after = base
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = after.split('/').next().unwrap_or("").trim();
    if host.is_empty() {
        return Err(format!("base_url '{base}' has no host"));
    }
    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZdrTargetSpec;

    fn spec(name: &str, base: &str, from_env: Option<&str>) -> ZdrTargetSpec {
        ZdrTargetSpec {
            name: name.into(),
            base_url: base.into(),
            trust_basis: Some("self_hosted".into()),
            user_verified: true,
            from_env: from_env.map(str::to_string),
            extra_headers: HashMap::new(),
        }
    }

    #[test]
    fn host_parsing() {
        assert_eq!(host_of("http://127.0.0.1:8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(
            host_of("https://bedrock.us-east-1.amazonaws.com/x").unwrap(),
            "bedrock.us-east-1.amazonaws.com"
        );
        assert!(host_of("http://").is_err());
    }

    #[test]
    fn oauth_shaped_credential_is_rejected() {
        assert!(reject_subscription_shaped("sk-ant-oat01-abc").is_err());
        assert!(reject_subscription_shaped("Bearer sk-ant-oat01-abc").is_err());
        // A real API key shape and an empty (no-auth) credential pass.
        assert!(reject_subscription_shaped("sk-ant-api03-abc").is_ok());
        assert!(reject_subscription_shaped("").is_ok());
    }

    #[test]
    fn resolve_registers_verified_target_with_key() {
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZDR_TEST_KEY_OK", "sk-ant-api03-deadbeef") };
        let section = ZdrSection {
            default: Some("box".into()),
            target: vec![spec("box", "http://127.0.0.1:8080/", Some("ZDR_TEST_KEY_OK"))],
        };
        let resolved = resolve_targets(&section);
        assert!(resolved.errors.is_empty(), "{:?}", resolved.errors);
        assert_eq!(resolved.default.as_deref(), Some("box"));
        let t = resolved.targets.get("box").expect("registered");
        assert_eq!(t.base_url, "http://127.0.0.1:8080", "trailing slash trimmed");
        assert_eq!(t.host, "127.0.0.1:8080");
        assert!(t.user_verified);
        assert_eq!(t.key().as_str(), "sk-ant-api03-deadbeef");
        // The value-free view must never carry the key bytes.
        let v = serde_json::to_value(t.view()).unwrap();
        assert_eq!(v["has_key"], serde_json::json!(true));
        assert!(
            !serde_json::to_string(&v).unwrap().contains("deadbeef"),
            "view must not leak the key"
        );
        unsafe { std::env::remove_var("ZDR_TEST_KEY_OK") };
    }

    #[test]
    fn resolve_rejects_oauth_target_and_drops_dangling_default() {
        // SAFETY: single-threaded unit test.
        unsafe { std::env::set_var("ZDR_TEST_KEY_OAUTH", "sk-ant-oat01-subscription") };
        let section = ZdrSection {
            default: Some("bad".into()),
            target: vec![spec(
                "bad",
                "http://127.0.0.1:8080",
                Some("ZDR_TEST_KEY_OAUTH"),
            )],
        };
        let resolved = resolve_targets(&section);
        assert!(!resolved.targets.contains_key("bad"), "OAuth target dropped");
        assert!(resolved.default.is_none(), "dangling default dropped");
        assert!(resolved.errors.iter().any(|e| e.contains("ToS")));
        unsafe { std::env::remove_var("ZDR_TEST_KEY_OAUTH") };
    }

    #[test]
    fn unset_env_resolves_to_no_auth_target() {
        let section = ZdrSection {
            default: None,
            target: vec![spec(
                "noauth",
                "http://127.0.0.1:9000",
                Some("ZDR_TEST_KEY_DEFINITELY_UNSET"),
            )],
        };
        let resolved = resolve_targets(&section);
        let t = resolved.targets.get("noauth").expect("registered no-auth");
        assert!(t.key().is_empty(), "unset env ⇒ no-auth");
    }
}

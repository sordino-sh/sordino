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
    /// Construct + validate a target from already-resolved parts (the credential is
    /// the resolved VALUE, not an env-var name). [`resolve_targets`] reads the env
    /// var then calls this; other callers construct directly. Enforces the same
    /// guards as resolution: ToS subscription-shape rejection (on the credential and
    /// every extra-header value) and `url::Url` base-url validation.
    pub fn new(
        name: String,
        base_url: &str,
        trust_basis: TrustBasis,
        user_verified: bool,
        extra_headers: Vec<(String, String)>,
        key: String,
    ) -> Result<ZdrTarget, String> {
        if name.trim().is_empty() {
            return Err("empty name".into());
        }
        reject_subscription_shaped(key.trim())?;
        // Defense-in-depth: a credential pasted into a (benign-named) extra header is
        // still a credential. (Auth-bearing header NAMES are rejected at config load.)
        for (hk, hv) in &extra_headers {
            reject_subscription_shaped(hv).map_err(|e| format!("extra_headers['{hk}'] {e}"))?;
        }
        let (base_url, host) = parse_base_url(base_url)?;
        Ok(ZdrTarget {
            name,
            base_url,
            host,
            trust_basis,
            user_verified,
            extra_headers,
            key: ZdrKey(key.trim().to_string()),
        })
    }

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
    let trust_basis = match spec.trust_basis.as_deref() {
        Some(s) => TrustBasis::parse(s)?,
        // Most conservative default: no declared basis ⇒ you are the anchor.
        None => TrustBasis::SelfHosted,
    };
    // Resolve the credential from its env var (refs-only; never inline — enforced by
    // the config scope invariant). Unset ⇒ no key (allowed for a no-auth self-hosted
    // box); present-but-OAuth-shaped ⇒ a hard ToS rejection (in `ZdrTarget::new`).
    let key = match spec.from_env.as_deref() {
        Some(var) => std::env::var(var).unwrap_or_default(),
        None => String::new(),
    };
    let extra_headers = spec
        .extra_headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    ZdrTarget::new(
        spec.name.clone(),
        &spec.base_url,
        trust_basis,
        spec.user_verified,
        extra_headers,
        key,
    )
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
    // Anthropic OAuth subscription access token.
    let oat = lower.starts_with("sk-ant-oat");
    // A `Bearer <tok>` / `OAuth …` paste — tolerant of ANY ASCII whitespace after the
    // scheme word (a literal-space prefix check missed `Bearer\t…`).
    let scheme = lower.split_ascii_whitespace().next().unwrap_or("");
    let bearer = scheme == "bearer" || scheme == "oauth";
    if oat || bearer {
        return Err("credential looks like a subscription / OAuth token (sk-ant-oat… / Bearer …). \
                    A ZDR key MUST be a non-subscription API key — using an OAuth subscription \
                    token in a third-party tool violates Anthropic's ToS. Refusing to register \
                    this target."
            .into());
    }
    Ok(())
}

/// Validate and split a ZDR `base_url` into `(canonical_base, host[:port])`. Uses a
/// real URL parser (not the lenient scheme-strip) so an ambiguous or hostile URL is
/// rejected at startup rather than silently routed somewhere unexpected:
///   - require an `http`/`https` scheme (a schemeless `localhost:8080` is refused);
///   - reject **userinfo** (`user:pass@host`) — `https://verified.example@evil.example`
///     routes to `evil.example`, NOT the reassuring name before the `@`, so it is a
///     spoofing footgun and a credential-in-URL smell. Refuse it outright;
///   - require a host.
/// The canonical base preserves the user's `scheme://host[:port][/path]` minus a
/// trailing slash (so `base + "/v1/messages"` is well-formed).
fn parse_base_url(base: &str) -> Result<(String, String), String> {
    let trimmed = base.trim();
    // Redacted form for ANY error/log line — never echo a credential, even when we
    // are rejecting the URL precisely BECAUSE it embeds one (these errors are logged
    // by `main.rs`, so an unredacted `user:secret@host` would land in the logs).
    let shown = redact_userinfo(trimmed);
    let u = url::Url::parse(trimmed)
        .map_err(|e| format!("base_url '{shown}' is not a valid URL: {e}"))?;
    match u.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "base_url '{shown}' must use http/https (got scheme '{other}')"
            ));
        }
    }
    if !u.username().is_empty() || u.password().is_some() {
        // Emit NO URL here — it carries a credential by definition.
        return Err("base_url must not embed userinfo (user:pass@host) — it would route to the \
             host AFTER the '@', not the name before it. Refusing (URL withheld: it carries a \
             credential)."
            .to_string());
    }
    // Host[:port], bracketing IPv6 literals so the Host header is well-formed
    // (`[::1]:8080`, not `::1:8080`).
    let host = match u.host().ok_or_else(|| format!("base_url '{shown}' has no host"))? {
        url::Host::Domain(d) => d.to_string(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => format!("[{ip}]"),
    };
    let host_port = match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    Ok((trimmed.trim_end_matches('/').to_string(), host_port))
}

/// Strip any `user:pass@` userinfo from a URL string before it is echoed in an
/// error/log line — a credential must never reach the logs even when the URL is
/// being rejected for containing one.
fn redact_userinfo(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after = scheme_end + 3;
        let authority_end = url[after..]
            .find('/')
            .map(|i| after + i)
            .unwrap_or(url.len());
        // The userinfo/host delimiter is the LAST `@` in the authority (a password
        // may itself contain a literal `@`, as `url::Url` parses it) — redacting at
        // the FIRST `@` would leave the password suffix exposed in the log line.
        if let Some(at_rel) = url[after..authority_end].rfind('@') {
            let at = after + at_rel;
            return format!("{}***@{}", &url[..after], &url[at + 1..]);
        }
    }
    url.to_string()
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
    fn base_url_parsing() {
        assert_eq!(
            parse_base_url("http://127.0.0.1:8080").unwrap(),
            ("http://127.0.0.1:8080".into(), "127.0.0.1:8080".into())
        );
        assert_eq!(
            parse_base_url("https://bedrock.us-east-1.amazonaws.com/x/").unwrap(),
            (
                "https://bedrock.us-east-1.amazonaws.com/x".into(),
                "bedrock.us-east-1.amazonaws.com".into()
            )
        );
        // No host, non-http scheme, and schemeless are all refused.
        assert!(parse_base_url("http://").is_err());
        assert!(parse_base_url("ftp://host").is_err());
        assert!(parse_base_url("localhost:8080").is_err());
        // Userinfo spoofing is refused (would route to evil.example).
        assert!(parse_base_url("https://verified.example@evil.example").is_err());
        assert!(parse_base_url("https://u:p@host.example").is_err());
        // IPv6 literals are bracketed for a well-formed Host header.
        assert_eq!(
            parse_base_url("http://[::1]:8080").unwrap().1,
            "[::1]:8080"
        );
        assert_eq!(parse_base_url("http://[::1]").unwrap().1, "[::1]");
    }

    #[test]
    fn userinfo_rejection_does_not_echo_credential() {
        let err = parse_base_url("https://user:supersecret@evil.example").unwrap_err();
        assert!(
            !err.contains("supersecret"),
            "rejection must not echo the credential: {err}"
        );
    }

    #[test]
    fn redact_userinfo_strips_creds() {
        assert_eq!(redact_userinfo("https://u:p@host/x"), "https://***@host/x");
        assert_eq!(redact_userinfo("https://host/x"), "https://host/x");
        assert_eq!(redact_userinfo("http://a:b@h"), "http://***@h");
        // A password containing a literal `@`: redact through the LAST authority `@`
        // (the userinfo/host delimiter) so no password suffix survives.
        assert_eq!(
            redact_userinfo("ftp://user:p@ss@host/x"),
            "ftp://***@host/x"
        );
        // `@` only in the path is not userinfo — left untouched.
        assert_eq!(redact_userinfo("https://host/a@b"), "https://host/a@b");
    }

    #[test]
    fn oauth_shaped_credential_is_rejected() {
        assert!(reject_subscription_shaped("sk-ant-oat01-abc").is_err());
        assert!(reject_subscription_shaped("Bearer sk-ant-oat01-abc").is_err());
        // Whitespace-tolerant: a tab after the scheme is still a bearer paste.
        assert!(reject_subscription_shaped("Bearer\tsk-ant-api03-abc").is_err());
        assert!(reject_subscription_shaped("  oauth   tok").is_err());
        // A real API key shape and an empty (no-auth) credential pass; a token that
        // merely starts with the letters "bearer" (no whitespace) is not a paste.
        assert!(reject_subscription_shaped("sk-ant-api03-abc").is_ok());
        assert!(reject_subscription_shaped("bearertoken-not-a-scheme").is_ok());
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
    fn oauth_value_in_benign_header_is_rejected_at_resolution() {
        // A benign-named header (config validator wouldn't flag the NAME) carrying an
        // OAuth-shaped VALUE must still be refused at resolution (defense-in-depth).
        let mut s = spec("box", "http://127.0.0.1:8080", None);
        s.extra_headers
            .insert("x-custom".into(), "Bearer sk-ant-oat01-subscription".into());
        let section = ZdrSection {
            default: None,
            target: vec![s],
        };
        let resolved = resolve_targets(&section);
        assert!(!resolved.targets.contains_key("box"));
        assert!(resolved.errors.iter().any(|e| e.contains("extra_headers")));
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

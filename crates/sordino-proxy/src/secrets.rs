//! Startup secret resolution + readiness status.
//!
//! Turns the config's `[[secrets]]` refs into engine `SecretRule`s by resolving each
//! through the `sordino-secrets` provider registry, then installs them via
//! `MaskEngine::set_secret_rules`. A REQUIRED secret that fails to resolve holds the
//! readiness gate closed (fail-closed). Secret VALUES never appear here past the
//! moment they are handed to the engine; the recorded [`SecretsStatus`] is
//! value-free (names/operators/scheme/resolved/required only).

use serde::Serialize;
use sordino_engine::{
    BrokerAllow, BrokerPolicy, DestRule, MaskEngine, Operator, SecretRule, SecretValue, slugify,
};
use sordino_secrets::{Eligibility, ProviderRegistry, SecretRef, classify};

use crate::config::{BrokerAllowSpec, SecretSpec};

/// Reserved name for the proxy's OWN admin (control) token. It is registered with the
/// `Local` ("owner-reveal") operator: masked on the wire (the provider sees the token
/// `[SORDINO_ADMIN_KEY_<hex>]`), REVEALED on the display path so the model can relay a
/// working monitor URL to the user, and REFUSED into tool inputs (the `Local` class
/// denies the tool path; it is not a broker token, so it never reaches `broker_resolve`).
/// A model-echoed admin token therefore reaches the user but never a tool/provider.
pub const ADMIN_KEY_SECRET_NAME: &str = sordino_engine::RESERVED_NONDEREF_SECRET;

/// The reserved `Local` rule that masks the proxy's admin key. PREPENDED into the
/// installed rule set so it is ALWAYS present — even for a no-secret project whose
/// background resolve never runs — and survives the REPLACE semantics of
/// [`MaskEngine::set_secret_rules`] (the background install re-prepends it).
pub fn admin_key_rule(admin_key: &str) -> SecretRule {
    SecretRule {
        name: ADMIN_KEY_SECRET_NAME.to_string(),
        value: SecretValue::new(admin_key.to_string()),
        // `Local` (owner-reveal): revealed to the user on display, refused into tools.
        operator: Operator::Local,
        case_sensitive: true,
        apply_to_surfaces: None,
    }
}

/// Build the default-deny broker policy from `[[broker.allow]]` config rules,
/// compiling tool/param/secret globs and parsing the optional `dest` constraint.
pub fn build_broker_policy(specs: &[BrokerAllowSpec]) -> Result<BrokerPolicy, String> {
    let mut allow = Vec::with_capacity(specs.len());
    for s in specs {
        let dest = parse_dest(s.dest.as_deref())?;
        let ttl = s.ttl_secs.map(std::time::Duration::from_secs);
        let rule = BrokerAllow::new(s.secret.as_deref(), &s.tool, &s.param, dest, ttl)
            .map_err(|e| e.to_string())?;
        allow.push(rule);
    }
    Ok(BrokerPolicy { allow })
}

fn parse_dest(spec: Option<&str>) -> Result<Option<DestRule>, String> {
    match spec {
        None => Ok(None),
        Some("any") => Ok(Some(DestRule::AnyHost)),
        Some(s) => {
            let Some(rest) = s.strip_prefix("host_allowlist:") else {
                return Err(format!(
                    "unknown dest {s:?} (use `any` or `host_allowlist:host1,host2`)"
                ));
            };
            let hosts: Vec<String> = rest
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();
            if hosts.is_empty() {
                return Err(format!("dest host_allowlist is empty in {s:?}"));
            }
            Ok(Some(DestRule::HostAllowList(hosts)))
        }
    }
}

/// Per-secret resolution outcome for the admin snapshot. NEVER carries a value.
#[derive(Clone, Debug, Serialize)]
pub struct SecretRuntimeEntry {
    pub name: String,
    pub operator: String,
    pub scheme: String,
    pub required: bool,
    pub resolved: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SecretsStatus {
    pub entries: Vec<SecretRuntimeEntry>,
}

impl SecretsStatus {
    pub fn resolved(&self) -> usize {
        self.entries.iter().filter(|e| e.resolved).count()
    }
    pub fn required(&self) -> usize {
        self.entries.iter().filter(|e| e.required).count()
    }
}

fn spec_to_ref(spec: &SecretSpec) -> Result<SecretRef, String> {
    match (&spec.from_ref, &spec.from_env) {
        // Don't echo the raw ref into the serialized status (round-2 F3) — a generic
        // safe message; the operator can see their own config for the exact ref.
        (Some(r), None) => SecretRef::parse(r)
            .map_err(|_| "invalid from_ref (expected scheme:path[#field])".to_string()),
        (None, Some(v)) => Ok(SecretRef::new("env", v.clone())),
        (Some(_), Some(_)) => Err(format!(
            "secret {:?}: set only one of from_ref / from_env",
            spec.name
        )),
        (None, None) => Err(format!(
            "secret {:?}: needs a from_ref or from_env reference",
            spec.name
        )),
    }
}

/// Parse a config operator string (`Token`/`Keep` are NOT offered — a secret must be
/// irreversible or broker).
fn parse_operator(s: &str) -> Result<Operator, String> {
    Ok(match s {
        "hash" => Operator::Hash,
        "redact" => Operator::Redact,
        "broker" => Operator::Broker,
        "mask" => Operator::Mask {
            char: '*',
            from_end: 4,
        },
        other => {
            return Err(format!(
                "unknown operator {other:?} (use hash|redact|mask|broker)"
            ));
        }
    })
}

/// Default operator for a secret with no explicit `operator =`: the classifier's
/// entropy choice (Hash for high-entropy, Redact for low). An explicit config entry
/// is always masked (never skipped), so a classifier `Skip` still defaults to Hash.
fn default_operator(name: &str, value: &str) -> Operator {
    match classify(name, value) {
        Eligibility::Eligible { operator, .. } => operator,
        Eligibility::Skip(_) => Operator::Hash,
    }
}

fn operator_name(op: Operator) -> String {
    match op {
        Operator::Token => "token",
        Operator::Redact => "redact",
        Operator::Mask { .. } => "mask",
        Operator::Hash => "hash",
        Operator::Broker => "broker",
        Operator::Local => "local",
        Operator::Keep => "keep",
    }
    .to_string()
}

/// A SAFE, variant-derived reason for a provider failure — never the raw error text
/// (which can carry backend stderr). Surfaced in the serialized status + hooks; the
/// full (sanitized) detail goes only to the local proxy log.
fn safe_reason(e: &sordino_secrets::ProviderError) -> String {
    use sordino_secrets::ProviderError as E;
    match e {
        E::NotFound => "not found".into(),
        // The binary NAME is a non-secret config fact; safe + useful to surface.
        E::BinaryMissing(b) => format!("backend binary `{b}` not found"),
        E::Spawn(_) => "backend spawn failed".into(),
        E::Auth(_) => "authentication/decryption failed (see proxy log)".into(),
        E::Parse(_) => "could not parse backend output".into(),
        E::Unsupported(_) => "unsupported reference for this backend".into(),
        E::Io(_) => "io error".into(),
        E::BadRef(_) => "invalid secret reference".into(),
    }
}

/// Record a failed resolution; a REQUIRED failure clears the readiness signal.
fn push_fail(
    entries: &mut Vec<SecretRuntimeEntry>,
    all_required_ok: &mut bool,
    spec: &SecretSpec,
    scheme: String,
    err: String,
) {
    if spec.required {
        *all_required_ok = false;
    }
    entries.push(SecretRuntimeEntry {
        name: spec.name.clone(),
        operator: spec.operator.clone().unwrap_or_else(|| "auto".into()),
        scheme,
        required: spec.required,
        resolved: false,
        error: Some(err),
    });
}

/// Resolve every spec via the registry and install the resolved ones into the
/// engine. Returns the value-free status (for the snapshot) and whether all REQUIRED
/// secrets resolved (the readiness-gate signal).
pub async fn resolve_and_install(
    specs: &[SecretSpec],
    engine: &MaskEngine,
    registry: &ProviderRegistry,
    admin_key: &str,
) -> (SecretsStatus, bool) {
    // PREPEND the reserved admin-key (Local) rule. It is never recorded in `entries`
    // (it needs no provider resolution and is always present), so it does not affect
    // `secrets_ready` accounting; prepending here means this REPLACE re-includes it
    // rather than clobbering the synchronous startup install.
    let mut rules: Vec<SecretRule> = vec![admin_key_rule(admin_key)];
    let mut entries: Vec<SecretRuntimeEntry> = Vec::new();
    let mut all_required_ok = true;

    for spec in specs {
        // The admin key is reserved (prepended above). A user secret of the same name
        // would shadow it or collide on the broker slug, so reject it REGARDLESS of
        // operator — the engine's slug-dedup in `compile_secrets` only fires for
        // `Broker`, so a `hash`/`redact`/`mask` namesake would otherwise slip through.
        // Compare on the canonical SLUG, not the literal name: `"sordino admin key"`,
        // `"Sordino-Admin-Key"`, etc. all slug to `SORDINO_ADMIN_KEY` and would collide
        // on the broker entity (pinning intake at 503 via a fail-closed install error).
        if slugify(&spec.name) == slugify(ADMIN_KEY_SECRET_NAME) {
            push_fail(
                &mut entries,
                &mut all_required_ok,
                spec,
                String::new(),
                format!("name {ADMIN_KEY_SECRET_NAME:?} is reserved for the proxy admin key"),
            );
            continue;
        }
        let sref = match spec_to_ref(spec) {
            Ok(r) => r,
            Err(e) => {
                push_fail(&mut entries, &mut all_required_ok, spec, String::new(), e);
                continue;
            }
        };
        let scheme = sref.scheme.clone();

        let value = match registry.resolve(&sref).await {
            Ok(v) => v,
            Err(e) => {
                // The full provider error may carry (bounded) backend stderr — keep it
                // in the LOCAL operator log only; the serialized status gets a SAFE
                // reason code (variant-derived), never the raw error text.
                tracing::warn!("sordino: secret {:?} failed to resolve: {e}", spec.name);
                push_fail(&mut entries, &mut all_required_ok, spec, scheme, safe_reason(&e));
                continue;
            }
        };

        let operator = match &spec.operator {
            Some(s) => match parse_operator(s) {
                Ok(o) => o,
                Err(e) => {
                    push_fail(&mut entries, &mut all_required_ok, spec, scheme, e);
                    continue;
                }
            },
            None => default_operator(&spec.name, value.expose()),
        };

        entries.push(SecretRuntimeEntry {
            name: spec.name.clone(),
            operator: operator_name(operator),
            scheme,
            required: spec.required,
            resolved: true,
            error: None,
        });
        rules.push(SecretRule {
            name: spec.name.clone(),
            value,
            operator,
            case_sensitive: spec.case_sensitive,
            apply_to_surfaces: None,
        });
    }

    if let Err(e) = engine.set_secret_rules(rules) {
        // e.g. a broker slug collision or invalid operator — surface and fail closed.
        tracing::error!("sordino: installing secret rules failed: {e}");
        all_required_ok = false;
        entries.push(SecretRuntimeEntry {
            name: "<install>".into(),
            operator: String::new(),
            scheme: String::new(),
            required: true,
            resolved: false,
            error: Some(e.to_string()),
        });
    }

    (SecretsStatus { entries }, all_required_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordino_engine::{EngineConfig, Surface};

    /// A plausible 64-hex control token for tests (the real one is blake3 of the AES key).
    const TEST_ADMIN_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn spec(name: &str, from_env: &str, op: Option<&str>, required: bool) -> SecretSpec {
        SecretSpec {
            name: name.into(),
            operator: op.map(str::to_string),
            from_ref: None,
            from_env: Some(from_env.into()),
            required,
            case_sensitive: true,
        }
    }

    #[tokio::test]
    async fn resolves_env_secret_and_masks() {
        let name = "SORDINO_PROXY_SECRETS_TEST_A1";
        unsafe { std::env::set_var(name, "SUPERSECRETVALUE9") };
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec("apitok", name, Some("hash"), true)];

        let (status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        unsafe { std::env::remove_var(name) };

        assert!(ok, "required env secret should resolve");
        assert_eq!(status.resolved(), 1);
        // The resolved secret is now masked by the engine.
        let out = engine
            .mask("use SUPERSECRETVALUE9 now", Surface::UserMessage)
            .unwrap();
        assert!(!out.masked_text.contains("SUPERSECRETVALUE9"));
        assert!(out.masked_text.contains("[APITOK:"));
        // Status carries no value.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("SUPERSECRETVALUE9"));
    }

    #[tokio::test]
    async fn missing_required_secret_fails_closed() {
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec(
            "missing",
            "SORDINO_PROXY_SECRETS_DEFINITELY_UNSET_ZZ",
            Some("hash"),
            true,
        )];
        let (status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        assert!(!ok, "a missing REQUIRED secret holds the gate closed");
        assert_eq!(status.resolved(), 0);
        assert_eq!(status.required(), 1);
    }

    #[tokio::test]
    async fn missing_optional_secret_does_not_fail_gate() {
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec(
            "opt",
            "SORDINO_PROXY_SECRETS_DEFINITELY_UNSET_YY",
            Some("hash"),
            false,
        )];
        let (_status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        assert!(ok, "a missing OPTIONAL secret must not hold the gate");
    }

    /// The admin key is registered `Local` (owner-reveal): masked on the wire, REVEALED on
    /// the display path (so the model relays a working monitor URL), but REFUSED into tool
    /// inputs. Installs even with NO config secrets (the no-secret-project case) and never
    /// appears in the value-free status.
    #[tokio::test]
    async fn admin_key_local_reveals_on_display_denies_tool() {
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let (status, ok) = resolve_and_install(&[], &engine, &registry, TEST_ADMIN_KEY).await;
        assert!(ok, "no required secrets ⇒ gate open");
        assert!(
            status.entries.is_empty(),
            "the admin rule must never appear in the value-free status"
        );

        // The bare admin key value is masked to the reserved LOCAL token — standard
        // `[ENTITY_xxx]` grammar, NOT a `[BROKER__…]` prefix (which would be display-refused).
        let out = engine
            .mask(&format!("the key is {TEST_ADMIN_KEY} now"), Surface::UserMessage)
            .unwrap();
        assert!(
            !out.masked_text.contains(TEST_ADMIN_KEY),
            "admin key egressed in plaintext: {:?}",
            out.masked_text
        );
        assert!(
            out.masked_text.contains("[SORDINO_ADMIN_KEY_"),
            "expected reserved Local token, got {:?}",
            out.masked_text
        );
        assert!(
            !out.masked_text.contains("[BROKER__"),
            "Local token must not carry the broker prefix (it must be display-revealable)"
        );

        // DISPLAY path (Arrow 2 → user): REVEALED, so the model relays a working URL.
        let shown = engine.unmask_assistant(&out.masked_text, &out.manifest).unwrap();
        assert!(
            shown.contains(TEST_ADMIN_KEY),
            "admin key must reveal on the display path: {shown:?}"
        );

        // TOOL-INPUT path (Arrow 3 → tool): NOT revealed — stays the token, so a model that
        // places it in a tool arg cannot exfiltrate it. This is the real deny gate.
        let tool = engine.unmask(&out.masked_text, &out.manifest).unwrap();
        assert!(
            !tool.contains(TEST_ADMIN_KEY),
            "admin key must NOT reveal on the tool-input path: {tool:?}"
        );
        assert!(tool.contains("[SORDINO_ADMIN_KEY_"));
    }

    /// The prepended admin rule survives a config-secret install (REPLACE semantics):
    /// BOTH the config secret AND the admin key stay masked, and the admin key stays
    /// reveal-on-display / deny-on-tool afterward.
    #[tokio::test]
    async fn admin_rule_survives_config_secret_install() {
        let name = "SORDINO_PROXY_SECRETS_TEST_COEXIST";
        unsafe { std::env::set_var(name, "COEXISTSECRET42") };
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec("apitok", name, Some("hash"), true)];
        let (_status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        unsafe { std::env::remove_var(name) };
        assert!(ok);

        let out = engine
            .mask(
                &format!("{TEST_ADMIN_KEY} and COEXISTSECRET42"),
                Surface::UserMessage,
            )
            .unwrap();
        assert!(
            !out.masked_text.contains(TEST_ADMIN_KEY),
            "admin rule was clobbered by the config-secret install"
        );
        assert!(!out.masked_text.contains("COEXISTSECRET42"));
        assert!(out.masked_text.contains("[SORDINO_ADMIN_KEY_"));

        // ...and the surviving admin token stays reveal-on-display / deny-on-tool.
        assert!(
            engine
                .unmask_assistant(&out.masked_text, &out.manifest)
                .unwrap()
                .contains(TEST_ADMIN_KEY),
            "admin key must still reveal on display after the REPLACE"
        );
        assert!(
            !engine
                .unmask(&out.masked_text, &out.manifest)
                .unwrap()
                .contains(TEST_ADMIN_KEY),
            "admin key must stay tool-denied after the config-secret REPLACE"
        );
    }

    /// A user secret named `sordino_admin_key` is rejected regardless of operator
    /// (here `hash`), and a REQUIRED one holds the gate closed.
    #[tokio::test]
    async fn reserved_admin_name_rejected() {
        let env = "SORDINO_PROXY_SECRETS_TEST_RESERVED";
        unsafe { std::env::set_var(env, "whatevervalue123") };
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec("sordino_admin_key", env, Some("hash"), true)];
        let (status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        unsafe { std::env::remove_var(env) };
        assert!(!ok, "a REQUIRED reserved-name secret must fail closed");
        assert_eq!(status.resolved(), 0);
        assert!(
            status
                .entries
                .iter()
                .any(|e| e.name.eq_ignore_ascii_case("sordino_admin_key") && !e.resolved),
            "the rejected reserved-name secret should be recorded as unresolved"
        );
    }

    /// A slug-VARIANT of the reserved name ("sordino admin key" → same SORDINO_ADMIN_KEY
    /// slug) is rejected too, so a broker namesake can't collide on the broker entity and
    /// pin intake at 503 via a fail-closed install error (Codex+Claude convergent finding).
    #[tokio::test]
    async fn reserved_admin_slug_variant_rejected() {
        let env = "SORDINO_PROXY_SECRETS_TEST_SLUGVAR";
        unsafe { std::env::set_var(env, "whatevervalue456") };
        let engine = MaskEngine::new(EngineConfig::default()).unwrap();
        let registry = sordino_secrets::default_registry(None);
        let specs = vec![spec("sordino admin key", env, Some("broker"), true)];
        let (status, ok) = resolve_and_install(&specs, &engine, &registry, TEST_ADMIN_KEY).await;
        unsafe { std::env::remove_var(env) };
        assert!(!ok, "a slug-colliding reserved namesake must be rejected");
        assert!(
            status.entries.iter().any(|e| !e.resolved
                && e.error.as_deref().map(|s| s.contains("reserved")).unwrap_or(false)),
            "rejection should be the reserved-name guard, not a downstream install error"
        );
    }
}

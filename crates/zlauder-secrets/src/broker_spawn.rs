//! The single process-spawn choke-point for the secrets crate.
//!
//! Every backend that shells out (pass/age/sops/…) goes through [`SecretBroker`].
//! Discipline enforced here, in one place:
//! - the secret arrives via **stdout only** — never argv (argv is world-readable in
//!   `/proc/<pid>/cmdline`), never an env var;
//! - **stdin is nulled** (no accidental prompt-fill / hang);
//! - the **environment is scrubbed** to an allowlist — the proxy's own env may carry
//!   OTHER secrets, so we do NOT inherit it; we re-add only what a credential CLI
//!   needs to find its config and reach its agent (gpg-agent / ssh-agent / age keys);
//! - `kill_on_drop` so a cancelled resolve can't leave a dangling `gpg`.

use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use crate::error::ProviderError;

/// Env vars passed through to a spawned backend CLI (everything else is cleared).
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "GNUPGHOME",
    "GPG_TTY",
    "GPG_AGENT_INFO",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    // Only FILE/agent pointers — never raw key MATERIAL. `SOPS_AGE_KEY` (the raw age
    // private key in the env) is deliberately NOT passed through: re-adding it after
    // env_clear() would re-expose a secret in the child's /proc/<pid>/environ. Use
    // SOPS_AGE_KEY_FILE (a path) instead.
    "SOPS_AGE_KEY_FILE",
    "AGE_KEY_FILE",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "PASSWORD_STORE_DIR",
];

/// The raw outcome of a spawn (used by health probes that must inspect a non-zero
/// exit rather than treat it as an error). Crate-internal: external callers use
/// [`SecretBroker::run`], which only ever returns stdout on success.
pub(crate) struct BrokerOutput {
    pub status_success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

pub struct SecretBroker;

impl SecretBroker {
    /// Run `argv` (argv\[0\] = binary), returning captured stdout on success.
    /// `Err(BinaryMissing)` if the binary isn't on PATH; `Err(Auth)` on a non-zero
    /// exit (stderr surfaced, never stdout — stdout may be the secret).
    pub async fn run(argv: &[String], cwd: Option<&Path>) -> Result<Vec<u8>, ProviderError> {
        let out = Self::probe(argv, cwd).await?;
        if !out.status_success {
            return Err(ProviderError::Auth(out.stderr));
        }
        Ok(out.stdout)
    }

    /// Like [`Self::run`] but returns the raw outcome (incl. exit status + stderr)
    /// without turning a non-zero exit into an error. Crate-internal (health probes).
    pub(crate) async fn probe(
        argv: &[String],
        cwd: Option<&Path>,
    ) -> Result<BrokerOutput, ProviderError> {
        let (bin, args) = argv
            .split_first()
            .ok_or_else(|| ProviderError::Spawn("empty argv".into()))?;
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for key in ENV_ALLOWLIST {
            if let Ok(v) = std::env::var(key) {
                cmd.env(key, v);
            }
        }
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProviderError::BinaryMissing(bin.clone())
            } else {
                ProviderError::Spawn(format!("{bin}: {e}"))
            }
        })?;
        // On failure, DROP stdout: a non-zero exit may have written partial secret
        // material to stdout, and no failure path needs it (health reads only
        // status+stderr; `run` returns stdout only on success).
        let success = output.status.success();
        Ok(BrokerOutput {
            status_success: success,
            stdout: if success { output.stdout } else { Vec::new() },
            stderr: sanitize_stderr(&output.stderr),
        })
    }
}

/// Bound the stderr we surface in `ProviderError::Auth`: take only the FIRST line and
/// cap it, so a misbehaving backend that writes secret material to stderr can leak at
/// most a short diagnostic snippet (auth errors like "gpg: decryption failed" are
/// short; a dumped secret is truncated). stdout — the value channel — is never
/// surfaced on failure.
fn sanitize_stderr(raw: &[u8]) -> String {
    const CAP: usize = 200;
    let s = String::from_utf8_lossy(raw);
    let first = s.lines().next().unwrap_or("").trim();
    let mut out: String = first.chars().take(CAP).collect();
    if first.chars().count() > CAP {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn secret_rides_stdout_not_argv() {
        // The whole point: a value comes back on stdout. `printf` writes its arg to
        // stdout; this asserts the broker captures stdout (the value channel).
        let out = SecretBroker::run(&["printf".into(), "%s".into(), "hunter2".into()], None)
            .await
            .unwrap();
        assert_eq!(out, b"hunter2");
    }

    #[tokio::test]
    async fn missing_binary_is_binary_missing() {
        let err = SecretBroker::run(&["zlauder-no-such-binary-xyz".into()], None)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::BinaryMissing(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn nonzero_exit_is_auth_error() {
        let err = SecretBroker::run(&["false".into()], None).await.unwrap_err();
        assert!(matches!(err, ProviderError::Auth(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn env_is_scrubbed() {
        // SAFETY: single-threaded test setup before the spawn.
        unsafe { std::env::set_var("ZLAUDER_SECRET_LEAK_CANARY", "leaked") };
        // `env` prints the (scrubbed) environment; the canary must be absent.
        let out = SecretBroker::run(&["env".into()], None).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("ZLAUDER_SECRET_LEAK_CANARY"),
            "proxy env leaked into the subprocess"
        );
        unsafe { std::env::remove_var("ZLAUDER_SECRET_LEAK_CANARY") };
    }
}

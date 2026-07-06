//! Listener binding: OS-assigned ephemeral (the default) vs a user-pinned static
//! port, with a loopback-only safety guard. Kept separate from `main` so the
//! mode/fallback logic is unit-testable without standing up the whole proxy.

use anyhow::{Context, Result};
use tokio::net::TcpListener;

/// Refuse to bind a non-loopback address unless explicitly acknowledged. The control
/// plane (`/sordino/reveal`, `/sordino/config`, the monitor) is only key-gated; a
/// LAN-reachable proxy turns it into a network-reachable PII-reveal oracle, so a
/// non-loopback bind is a hard opt-in, never the default.
pub fn loopback_guard(bind: &str) -> Result<()> {
    if sordino_state::is_loopback_bind(bind) {
        return Ok(());
    }
    if std::env::var_os("SORDINO_ALLOW_NON_LOOPBACK_BIND").is_some() {
        eprintln!(
            "Sordino: DANGER — binding {bind} exposes the control plane (reveal/config/monitor, \
             which can REVEAL real PII) beyond localhost. The admin-key gate is the only barrier. \
             Bind 127.0.0.1 unless you fully understand this. Proceeding because \
             SORDINO_ALLOW_NON_LOOPBACK_BIND is set."
        );
        tracing::warn!("binding non-loopback {bind} (ack via SORDINO_ALLOW_NON_LOOPBACK_BIND)");
        return Ok(());
    }
    anyhow::bail!(
        "refusing to bind non-loopback address {bind} — this would expose the reveal/config/monitor \
         control plane (which can reveal real PII) to the network. Use 127.0.0.1 (the default). If \
         you truly intend a reachable proxy, set SORDINO_ALLOW_NON_LOOPBACK_BIND=1."
    );
}

/// Bind the proxy's listener.
///
/// - `static_port = Some(n)`: a hard pin. Bind exactly `n`; on failure return a
///   classified, actionable error and DO NOT probe to another port (the user chose it).
/// - `static_port = None`: ephemeral. Try the project's sticky `last_port` first (so the
///   port stays stable across restarts and `settings.local.json` rarely churns), and
///   fall back to `127.0.0.1:0` (OS-assigned) if that seed is taken — including the
///   Windows `TIME_WAIT`-without-`SO_REUSEADDR` case, which makes sticky reuse advisory.
pub async fn bind_listener(
    bind: &str,
    static_port: Option<u16>,
    project_root: &str,
) -> Result<TcpListener> {
    match static_port {
        Some(p) => bind_exact(bind, p).await.map_err(|e| {
            let fault = sordino_state::classify_bind_error(e.raw_os_error(), e.kind());
            anyhow::anyhow!("{}", fault.message(p, bind))
        }),
        None => {
            if let Some(seed) = sordino_state::read_rendezvous(project_root)
                .map(|r| r.last_port)
                .filter(|p| *p != 0)
                && let Ok(listener) = bind_exact(bind, seed).await
            {
                return Ok(listener);
            }
            bind_exact(bind, 0)
                .await
                .with_context(|| format!("binding {bind}:0"))
        }
    }
}

async fn bind_exact(bind: &str, port: u16) -> std::io::Result<TcpListener> {
    // Pass host + port as a tuple (NOT `format!("{bind}:{port}")`): the string form
    // mangles an IPv6 literal (`::1` → `::1:0`, unparseable), whereas the `(host, port)`
    // ToSocketAddrs tuple binds `::1`/`127.0.0.1`/`localhost` correctly. Strip optional
    // brackets so a `[::1]` spelling (which the loopback guard accepts) also binds.
    let host = bind
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(bind);
    TcpListener::bind((host, port)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // SORDINO_STATE_DIR / SORDINO_ALLOW_NON_LOOPBACK_BIND are process-global; serialize
    // the tests that touch them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn loopback_guard_allows_loopback_refuses_public() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(loopback_guard("127.0.0.1").is_ok());
        assert!(loopback_guard("::1").is_ok());
        assert!(loopback_guard("localhost").is_ok());
        // Non-loopback is refused when the ack env is absent.
        // SAFETY: single-threaded under ENV_LOCK.
        unsafe { std::env::remove_var("SORDINO_ALLOW_NON_LOOPBACK_BIND") };
        assert!(loopback_guard("0.0.0.0").is_err());
        assert!(loopback_guard("192.168.1.10").is_err());
        // ...and admitted (with a warning) when acknowledged.
        unsafe { std::env::set_var("SORDINO_ALLOW_NON_LOOPBACK_BIND", "1") };
        assert!(loopback_guard("0.0.0.0").is_ok());
        unsafe { std::env::remove_var("SORDINO_ALLOW_NON_LOOPBACK_BIND") };
    }

    #[tokio::test]
    async fn ipv6_loopback_is_not_mangled() {
        // Regression: `format!("{bind}:{port}")` turned "::1" into the unparseable
        // "::1:0". The tuple form must either bind (IPv6-capable host) or fail for a
        // REAL reason (e.g. IPv6 disabled) — never an address-PARSE error.
        match bind_exact("::1", 0).await {
            Ok(l) => assert_ne!(l.local_addr().unwrap().port(), 0),
            Err(e) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "::1 must not be an address-parse failure: {e}"
            ),
        }
        // The bracketed spelling the guard accepts must also reach a real bind attempt.
        match bind_exact("[::1]", 0).await {
            Ok(l) => assert_ne!(l.local_addr().unwrap().port(), 0),
            Err(e) => assert_ne!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}"),
        }
    }

    #[tokio::test]
    async fn ephemeral_binds_a_real_port() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sordino-bind-eph-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::set_var("SORDINO_STATE_DIR", &dir) };
        let l = bind_listener("127.0.0.1", None, "/proj/eph").await.unwrap();
        assert_ne!(l.local_addr().unwrap().port(), 0, "ephemeral got a concrete port");
        unsafe { std::env::remove_var("SORDINO_STATE_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn static_pin_binds_exact_and_classifies_conflict() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sordino-bind-stat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::set_var("SORDINO_STATE_DIR", &dir) };
        // Hold an OS-assigned port, then pin a second listener to it → InUse, classified.
        let held = bind_listener("127.0.0.1", None, "/proj/s1").await.unwrap();
        let p = held.local_addr().unwrap().port();
        let err = bind_listener("127.0.0.1", Some(p), "/proj/s2")
            .await
            .expect_err("a busy static pin must error, not probe away");
        assert!(err.to_string().contains("already in use"), "got: {err}");
        unsafe { std::env::remove_var("SORDINO_STATE_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ephemeral_honors_sticky_seed_then_falls_back() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sordino-bind-stick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::set_var("SORDINO_STATE_DIR", &dir) };
        let root = "/proj/sticky";

        // Discover a free port, record it as the project's last_port, then release it.
        let seed = {
            let l = bind_listener("127.0.0.1", None, root).await.unwrap();
            l.local_addr().unwrap().port()
        };
        sordino_state::write_rendezvous(&sordino_state::Rendezvous {
            project_root: root.into(),
            port: 0,
            admin_key: String::new(),
            salt: String::new(),
            base_url: String::new(),
            pid: 0,
            bind: "127.0.0.1".into(),
            last_port: seed,
            build_id: String::new(),
            started_unix: 0,
            nonce: String::new(),
        })
        .unwrap();

        // Sticky seed is free → ephemeral binds EXACTLY it.
        let stuck = bind_listener("127.0.0.1", None, root).await.unwrap();
        assert_eq!(
            stuck.local_addr().unwrap().port(),
            seed,
            "a free sticky seed must be reused"
        );

        // Seed now held by `stuck` → a second ephemeral bind for the same project falls
        // back to a DIFFERENT OS-assigned port rather than erroring.
        let fallback = bind_listener("127.0.0.1", None, root).await.unwrap();
        let fb = fallback.local_addr().unwrap().port();
        assert_ne!(fb, seed, "a taken sticky seed must fall back to :0");
        assert_ne!(fb, 0);

        unsafe { std::env::remove_var("SORDINO_STATE_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}

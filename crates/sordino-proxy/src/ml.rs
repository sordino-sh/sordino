//! Hot (background) loading of the optional ML recognizer.
//!
//! Loading `openai/privacy-filter` is heavy (download + model load), so it runs
//! on a blocking pool while the proxy keeps serving — masking stays regex-only
//! until the model is `Ready` (the status line/`/sordino:privacy status` say so).
//!
//! Safety against the stale-load race: [`MaskEngine::ml_begin_load`] bumps a
//! generation and returns a token; the background task only installs its result
//! via [`MaskEngine::ml_set_ready`]/[`MaskEngine::ml_set_failed`] if that token is
//! still current. A turn-off or model change (which also bump the generation)
//! therefore discards any in-flight load instead of letting it resurrect.

use std::sync::Arc;

use sordino_engine::{MaskEngine, MlConfig, MlStatus};

use crate::state::AppState;

/// Spawn a background task that loads the model and installs the recognizer when
/// it finishes. Returns immediately.
pub fn spawn_ml_load(engine: Arc<MaskEngine>, ml: MlConfig) {
    let generation = engine.ml_begin_load(ml.clone());
    let model = ml.model.clone();
    tokio::spawn(async move {
        tracing::info!(model = %model, "loading openai-privacy model in background");
        let res =
            tokio::task::spawn_blocking(move || sordino_engine::ml::build_recognizer(&ml)).await;
        match res {
            Ok(Ok(rec)) => {
                engine.ml_set_ready(generation, rec);
                tracing::info!(model = %model, "openai-privacy model ready");
            }
            Ok(Err(e)) => {
                tracing::warn!(model = %model, error = %e, "openai-privacy model load failed");
                engine.ml_set_failed(generation, e.to_string());
            }
            Err(join) => {
                engine.ml_set_failed(generation, format!("load task panicked: {join}"));
            }
        }
    });
}

/// Reconcile the live ML runtime to a desired config. `retry_failed` is true
/// only for an explicit enable, so unrelated edits do not retry a broken model.
pub fn reconcile_ml(st: &AppState, new_ml: &MlConfig, retry_failed: bool) {
    let snap = st.engine.ml_snapshot();
    if !new_ml.enabled {
        if snap.status != MlStatus::Disabled {
            st.engine.ml_disable();
        }
        return;
    }
    // Enabled: (re)load if not already loading/ready the SAME model params.
    let params_changed = snap
        .desired
        .as_ref()
        .map(|d| !d.same_model_params(new_ml))
        .unwrap_or(true);
    let needs_load = match snap.status {
        MlStatus::Disabled => true,
        MlStatus::Failed => retry_failed || params_changed,
        MlStatus::Loading | MlStatus::Ready => params_changed,
    };
    if needs_load {
        // A spawned (re)load installs the WHOLE desired config (incl. `required`)
        // via `ml_begin_load`, so no separate `required` update is needed here.
        spawn_ml_load(st.engine.clone(), new_ml.clone());
    } else {
        // `required` is refusal policy, not recognizer identity; apply it live.
        st.engine.ml_update_required(new_ml.required);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use sordino_engine::{EngineConfig, InfallibleMl, MlBackend};

    use crate::config::ConfigLayers;
    use crate::monitor::Monitor;
    use crate::state::AppState;
    use crate::test_support::MarkerRecognizer;

    /// Minimal `AppState` for a reconcile unit test — reconcile_ml only touches
    /// `st.engine`; every other field is an inert default (mirrors the integration
    /// test's `mk_state`, kept local so this stays a same-crate unit test).
    fn mk_state(engine: MaskEngine) -> AppState {
        AppState {
            engine: Arc::new(engine),
            http: reqwest::Client::new(),
            upstream_base: Arc::new("http://127.0.0.1:0".into()),
            admin_key: Arc::new("k".into()),
            layers: Arc::new(ConfigLayers {
                user: std::path::PathBuf::from("/nonexistent/sordino/config.toml"),
                project: None,
                local: None,
            }),
            project_root: Arc::new("/tmp/sordino-test-project".into()),
            port: 0,
            monitor: Monitor::new(),
            ledger: None,
            ml_control: Arc::new(std::sync::Mutex::new(())),
            config_control: Arc::new(std::sync::Mutex::new(())),
            secrets_ready: Arc::new(AtomicBool::new(true)),
            secrets_status: Arc::new(std::sync::RwLock::new(
                crate::secrets::SecretsStatus::default(),
            )),
            zdr_targets: Arc::new(std::collections::HashMap::new()),
            zdr_default: Arc::new(None),
            zdr_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            masking_disabled: Arc::new(std::sync::Mutex::new(
                crate::state::MaskingDisabled::default(),
            )),
        }
    }

    /// A remote (non-loopback) http ML config, opted-in or not.
    fn remote_http(allow: bool) -> MlConfig {
        MlConfig {
            enabled: true,
            backend: MlBackend::Http,
            endpoint: Some("https://inference.example.com/classify".into()),
            allow_remote_ml_endpoint: allow,
            ..Default::default()
        }
    }

    /// FAIL-OPEN FIX (A6, threat model L17): a live `allow_remote_ml_endpoint`
    /// true->false flip on a Ready remote http backend must force a reload (because
    /// `same_model_params` now reports the identity CHANGED), which re-runs
    /// http_config's non-loopback refuse-check and fails CLOSED. The stale
    /// remote-calling recognizer is cleared synchronously the instant the reload
    /// begins, and the reload lands in `Failed` with the L17 refusal. No live
    /// network: http_config refuses before any request is issued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn allow_flip_forces_reload_that_refuses_and_clears_recognizer() {
        // Seed a Ready remote backend as if it had loaded earlier under allow=true.
        let engine = MaskEngine::new(EngineConfig::default()).expect("engine init");
        let generation = engine.ml_begin_load(remote_http(true));
        engine.ml_set_ready(
            generation,
            Arc::new(InfallibleMl(Arc::new(MarkerRecognizer::new("<<MARK>>")))),
        );
        assert!(engine.ml_active(), "precondition: remote backend must be Ready");
        let st = mk_state(engine);

        // Live-reconfigure: SAME endpoint, allow flipped to false. `same_model_params`
        // must now report the identity CHANGED (the A6 identity coupling), so reconcile
        // spawns a reload rather than treating it as an inert `required`-only edit.
        reconcile_ml(&st, &remote_http(false), false);

        // `ml_begin_load` (inside the spawned reload) clears the recognizer to None
        // synchronously — the stale remote-calling recognizer stops immediately.
        assert!(
            !st.engine.ml_active(),
            "the stale remote recognizer must be cleared the instant the reload begins"
        );

        // The background reload runs http_config, which REFUSES the non-loopback
        // endpoint (no network) → status Failed carrying the L17 refusal message.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snap = st.engine.ml_snapshot();
            if snap.status == MlStatus::Failed {
                let err = snap.error.unwrap_or_default();
                assert!(
                    err.contains("non-loopback"),
                    "the refused reload must carry the L17 refusal, got: {err}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "reload never reached Failed (status {:?})",
                snap.status
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !st.engine.ml_active(),
            "a refused reload must leave ML inactive (recognizer None), not Ready"
        );
    }
}

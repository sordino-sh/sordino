//! Hot (background) loading of the optional ML recognizer.
//!
//! Loading `openai/privacy-filter` is heavy (download + model load), so it runs
//! on a blocking pool while the proxy keeps serving — masking stays regex-only
//! until the model is `Ready` (the status line/`/zlauder:privacy status` say so).
//!
//! Safety against the stale-load race: [`MaskEngine::ml_begin_load`] bumps a
//! generation and returns a token; the background task only installs its result
//! via [`MaskEngine::ml_set_ready`]/[`MaskEngine::ml_set_failed`] if that token is
//! still current. A turn-off or model change (which also bump the generation)
//! therefore discards any in-flight load instead of letting it resurrect.

use std::sync::Arc;

use zlauder_engine::{MaskEngine, MlConfig, MlStatus};

use crate::state::AppState;

/// Spawn a background task that loads the model and installs the recognizer when
/// it finishes. Returns immediately.
pub fn spawn_ml_load(engine: Arc<MaskEngine>, ml: MlConfig) {
    let generation = engine.ml_begin_load(ml.clone());
    let model = ml.model.clone();
    tokio::spawn(async move {
        tracing::info!(model = %model, "loading openai-privacy model in background");
        let res =
            tokio::task::spawn_blocking(move || zlauder_engine::ml::build_recognizer(&ml)).await;
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

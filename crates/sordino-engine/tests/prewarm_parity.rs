//! Real-model recall gate for the batched-detection prewarm (engine-walker batch
//! wiring). Masking a corpus WITH `prewarm_batch` must be byte-identical — masked
//! text AND minted tokens — to masking each leaf straight through `mask`, using the
//! REAL `openai/privacy-filter` model. This is the empirical end of the recall
//! contract: the per-leaf path is the proven reference; prewarm (which routes the
//! ML detection through `Recognizer::analyze_batch` instead of looped `analyze`)
//! must not change a single masked span.
//!
//! The engine-level `prewarm_then_mask_matches_unprewarmed` unit test pins the
//! wiring with a mock recognizer; THIS test pins the real batched candle forward
//! (incl. the padded banded-attention path) against the looped forward through the
//! full engine (detection → cache → apply).
//!
//! Marked `#[ignore]`: needs the ~2.8 GB model (cached after first run).
//!
//! ```
//! cargo test -p sordino-engine --features ml --test prewarm_parity -- --ignored --nocapture
//! ```

#![cfg(feature = "ml")]

use sordino_engine::{EngineConfig, MaskEngine, MaskOutcome, MlConfig, Surface};

/// Two engines must mint identical tokens, so fix the session key + salt.
const KEY: [u8; 32] = [11u8; 32];
const SALT: [u8; 16] = [22u8; 16];

/// A `MaskEngine` with the real privacy-filter recognizer `Ready`.
fn engine_with_real_ml() -> MaskEngine {
    let engine =
        MaskEngine::with_session(EngineConfig::default(), KEY, SALT).expect("engine init");
    let recognizer =
        sordino_engine::ml::build_recognizer(&MlConfig::default()).expect("model load");
    let generation = engine.ml_begin_load(MlConfig::default());
    engine.ml_set_ready(generation, recognizer);
    assert!(engine.ml_active(), "real ML should be Ready");
    engine
}

/// A leaf's masked text plus its minted (token, plaintext) pairs, sorted so the
/// comparison is order-independent.
fn fingerprint(out: &MaskOutcome) -> (String, Vec<(String, String)>) {
    let mut toks: Vec<(String, String)> = out
        .manifest
        .entries
        .iter()
        .map(|e| (e.token_handle.clone(), e.canonical_form.clone()))
        .collect();
    toks.sort();
    (out.masked_text.clone(), toks)
}

/// Corpus mixing PII kinds, surfaces, lengths (incl. a long banded-path text),
/// duplicates, and a no-PII leaf — the same shapes the presidio batch-parity gate
/// stresses, but driven through the whole sordino engine.
fn corpus() -> Vec<(String, Surface)> {
    let long = {
        let mut s = String::new();
        for i in 0..40 {
            s.push_str(&format!(
                "Record {i}: contact Dr. Jane Doe at jane.doe{i}@example.com about \
                 invoice {i} dated 2026-01-{day:02} in Berlin. ",
                day = (i % 28) + 1
            ));
        }
        s
    };
    vec![
        ("Contact Bob Smith at bob.smith@corp.io or call +1 415 555 0142.".into(), Surface::UserMessage),
        ("no personal data in this ordinary tool output line".into(), Surface::ToolResult),
        ("The sync with Dr. Jane Doe is on 2026-04-29 in Berlin.".into(), Surface::SystemPrompt),
        ("Contact Bob Smith at bob.smith@corp.io or call +1 415 555 0142.".into(), Surface::UserMessage), // dup
        ("Reach Carol at carol@team.dev — she moved to Seattle.".into(), Surface::AssistantText),
        ("ping".into(), Surface::ToolResult),
        (long, Surface::UserMessage), // long ⇒ banded path under batching
        ("My SSN is 536-90-4399 and card 4111 1111 1111 1111.".into(), Surface::UserMessage),
    ]
}

#[test]
#[ignore = "downloads/loads ~2.8 GB model; gate via `--ignored`"]
fn prewarm_parity_real_model() {
    let leaves = corpus();

    // Path A — per-leaf mask, no prewarm (the proven reference).
    let a = engine_with_real_ml();
    let mut a_ml_ran = 0u32;
    let out_a: Vec<(String, Vec<(String, String)>)> = leaves
        .iter()
        .map(|(t, s)| {
            let o = a.mask(t, *s).expect("mask");
            a_ml_ran += o.stats.ml_ran;
            fingerprint(&o)
        })
        .collect();

    // Path B — batch-prewarm the whole corpus, then per-leaf mask.
    let b = engine_with_real_ml();
    let refs: Vec<(&str, Surface)> = leaves.iter().map(|(t, s)| (t.as_str(), *s)).collect();
    b.prewarm_batch(&refs);
    let mut b_ml_ran = 0u32;
    let out_b: Vec<(String, Vec<(String, String)>)> = leaves
        .iter()
        .map(|(t, s)| {
            let o = b.mask(t, *s).expect("mask");
            b_ml_ran += o.stats.ml_ran;
            fingerprint(&o)
        })
        .collect();

    // Recall contract: every leaf's masked text AND minted tokens are identical.
    for (i, ((ta, _), (tb, _))) in out_a.iter().zip(&out_b).enumerate() {
        assert_eq!(
            ta, tb,
            "leaf {i} masked text differs:\n  per-leaf: {ta}\n  prewarmed: {tb}"
        );
    }
    assert_eq!(out_a, out_b, "prewarm changed masked text or minted tokens");

    // Effectiveness: prewarm ran ALL the ML detection up front, so the per-leaf mask
    // pass re-ran zero inferences — while the per-leaf reference ran ML on every
    // unique leaf. This is the throughput win the wiring exists for.
    assert_eq!(b_ml_ran, 0, "prewarm should leave nothing for per-leaf ML to run");
    assert!(
        a_ml_ran > 0,
        "reference path should have run ML on the unique leaves"
    );

    eprintln!(
        "prewarm parity OK across {} leaves; reference ml_ran={}, prewarmed per-leaf ml_ran={}",
        leaves.len(),
        a_ml_ran,
        b_ml_ran
    );
}

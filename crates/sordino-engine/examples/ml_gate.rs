//! Recall + perf GATE harness for the ML recognizer (`openai/privacy-filter`).
//!
//! This is the safety net for the CPU-optimization work in `presidio-rs`. The
//! invariant it protects is: **recall == privacy**. A change to the model code
//! (f16, Q8, attention/MoE rewrites, the long-`T` "P1" path) must NEVER drop a
//! true-positive PII span that the unmodified baseline detected — a dropped span
//! egresses as plaintext. This harness captures a golden snapshot of the baseline
//! and then fails loudly if any later build loses a span or regresses recall.
//!
//! Unlike `profile_bench` (ML OFF), this builds the engine under the **Strict**
//! profile with the **ML recognizer ENABLED and loaded synchronously**, so the
//! ML-unique PERSON/LOCATION spans — the spans most sensitive to f16/Q8/P1 — are
//! live and gated.
//!
//! Two signals per needle:
//!   - `hit`  : authoritative end-to-end — did `engine.mask()` actually mask the
//!              needle (manifest entry of the expected kind overlapping it, OR the
//!              needle no longer appears verbatim in the masked text). A dropped
//!              `hit` is the regression that matters.
//!   - `score`: the ML recognizer's reported confidence for the best result whose
//!              span overlaps the needle (captured by calling the recognizer's
//!              `analyze()` directly). This is the fine-grained drift signal —
//!              a numeric kernel change shifts scores before it drops a hit.
//!
//! Usage:
//!   ml_gate --dump-golden <path>
//!   ml_gate --check-golden <path> [--tol <f>]   (default tol 1e-3)
//!
//! Exits nonzero on FAIL so a CI/loop caller can detect a regression.

// The module doc's nested signal list is intentionally indented for readability;
// the (cosmetic) overindented-list lint doesn't earn a prose reflow here.
#![allow(clippy::doc_overindented_list_items)]

// The harness is meaningless without the ML backend; under a regex-only build it
// compiles to a clear stub so `cargo build --examples` (no `ml`) still succeeds.
#[cfg(not(feature = "ml"))]
fn main() -> std::process::ExitCode {
    eprintln!("ml_gate requires the `ml` feature: rebuild with --features ml");
    std::process::ExitCode::from(2)
}

#[cfg(feature = "ml")]
use ml_gate_impl::main as gated_main;

#[cfg(feature = "ml")]
fn main() -> std::process::ExitCode {
    gated_main()
}

#[cfg(feature = "ml")]
mod ml_gate_impl {
    use std::collections::BTreeMap;
    use std::process::ExitCode;
    use std::time::Instant;

    use sordino_engine::MlRecognizer;
    use serde_json::{Value, json};

    use sordino_engine::{EngineConfig, MaskEngine, MlConfig, Profile, Surface};

    // ---------------------------------------------------------------------------
    // Corpus
    // ---------------------------------------------------------------------------

    /// A positive sample: `text` should mask `needle` as entity `kind`.
    struct Positive {
        kind: &'static str,
        needle: &'static str,
        text: &'static str,
    }

    impl Positive {
        const fn new(kind: &'static str, needle: &'static str, text: &'static str) -> Self {
            Self { kind, needle, text }
        }
    }

    /// Long-document prose fixtures (~2000+ tokens) with PII needles embedded, so the
    /// long-`T` ("P1") inference path and per-doc perf are exercised. The `block` is a
    /// large filler paragraph repeated to push the token count up; the needles are
    /// spliced into the prose.
    fn long_doc(needles: &[(&'static str, &'static str)], lead: &str) -> String {
        // ~60-word filler paragraph; repeated to reach ~2000+ tokens.
        const FILLER: &str = "The quarterly operations review covered logistics throughput, \
warehouse utilization, and the regional distribution backlog that accumulated over the \
preceding fiscal period. Stakeholders discussed mitigation strategies, capacity planning, \
and the projected impact of seasonal demand on the supply chain network across all \
operating territories and partner facilities for the remainder of the calendar year. ";
        let mut s = String::with_capacity(16 * 1024);
        s.push_str(lead);
        s.push(' ');
        // Interleave needles into the prose so they are not all clustered at the front.
        for i in 0..32 {
            s.push_str(FILLER);
            if i % 4 == 0
                && let Some((_, sentence)) = needles.get(i % needles.len().max(1))
            {
                s.push_str(sentence);
                s.push(' ');
            }
        }
        s
    }

    /// Positives: the labeled regex-detectable spans from `profile_bench`, PLUS the
    /// ML-unique PERSON spans (which under Strict+ML SHOULD now hit), PLUS LOCATION
    /// spans (ML-unique, sensitive to numeric drift).
    fn short_positives() -> Vec<Positive> {
        use Positive as P;
        vec![
            // --- Emails ---------------------------------------------------------
            P::new(
                "EMAIL_ADDRESS",
                "alice@example.com",
                "contact alice@example.com please",
            ),
            P::new(
                "EMAIL_ADDRESS",
                "bob+newsletter@example.com",
                "subscribe bob+newsletter@example.com today",
            ),
            P::new(
                "EMAIL_ADDRESS",
                "carol.danvers+tag@sub.example.co.uk",
                "reply carol.danvers+tag@sub.example.co.uk soon",
            ),
            // --- Phones WITH context words --------------------------------------
            P::new(
                "PHONE_NUMBER",
                "+1 415 555 0132",
                "call me at +1 415 555 0132 tomorrow",
            ),
            P::new(
                "PHONE_NUMBER",
                "+1-415-555-0142",
                "my phone is +1-415-555-0142 ok",
            ),
            P::new(
                "PHONE_NUMBER",
                "(415) 555-0132",
                "reach me, number (415) 555-0132 anytime",
            ),
            P::new("PHONE_NUMBER", "415.555.0132", "phone 415.555.0132 is best"),
            P::new(
                "PHONE_NUMBER",
                "+44 20 7946 0958",
                "call the office at +44 20 7946 0958 now",
            ),
            // --- Identity -------------------------------------------------------
            P::new("US_SSN", "536-90-4399", "ssn 536-90-4399 on file"),
            // --- Financial ------------------------------------------------------
            P::new(
                "CREDIT_CARD",
                "4111111111111111",
                "visa 4111111111111111 charged",
            ),
            P::new(
                "CREDIT_CARD",
                "5555555555554444",
                "mastercard 5555555555554444 ok",
            ),
            P::new(
                "CREDIT_CARD",
                "378282246310005",
                "amex 378282246310005 declined",
            ),
            P::new(
                "IBAN_CODE",
                "GB82WEST12345698765432",
                "iban GB82WEST12345698765432 set",
            ),
            // --- Secrets --------------------------------------------------------
            P::new(
                "AWS_ACCESS_KEY",
                "AKIAIOSFODNN7EXAMPLE",
                "key AKIAIOSFODNN7EXAMPLE here",
            ),
            P::new(
                "AWS_SECRET_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
            P::new(
                "GCP_API_KEY",
                "AIzaSyC9x_8Kd2LmN4pQ6rS1tU3vW5yZ7aB0cEf",
                "gcp AIzaSyC9x_8Kd2LmN4pQ6rS1tU3vW5yZ7aB0cEf used",
            ),
            P::new(
                "JWT",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c works",
            ),
            P::new(
                "PRIVATE_KEY",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
            ),
            // --- Contact --------------------------------------------------------
            P::new("IP_ADDRESS", "203.0.113.42", "server at 203.0.113.42 down"),
            // --- ML-unique PERSON (Strict+ML => SHOULD hit) ---------------------
            P::new(
                "PERSON",
                "Alice Johnson",
                "please email Alice Johnson the report",
            ),
            P::new(
                "PERSON",
                "Maria Gonzalez",
                "Maria Gonzalez approved the request",
            ),
            // --- ML-unique LOCATION (numeric-drift sensitive) -------------------
            P::new(
                "LOCATION",
                "San Francisco",
                "the team relocated to San Francisco last spring",
            ),
            // --- Widened ML-unique PERSON corpus --------------------------------
            // Varied structure (apostrophe / hyphen / diacritic / non-Western /
            // single-token) with NO regex trigger word (no "Mr."/"Dr."), so each
            // span is genuinely the model's job. These broaden the ML-owned recall
            // denominator far past the original 6 spans so a low-precision lever
            // (bf16/f16/Q8) cannot pass the gate by only preserving a thin set.
            P::new("PERSON", "Wei Chen", "forward the signed deck to Wei Chen before noon"),
            P::new("PERSON", "Sarah O'Brien", "the panel will be chaired by Sarah O'Brien"),
            P::new(
                "PERSON",
                "Mohammed Al-Farsi",
                "the lease was countersigned by Mohammed Al-Farsi",
            ),
            P::new("PERSON", "Yuki Tanaka", "Yuki Tanaka transferred in from the Osaka desk"),
            P::new("PERSON", "Dmitri Volkov", "escalate the outage ticket to Dmitri Volkov"),
            P::new("PERSON", "Aisha Rahman", "the quarterly audit is led by Aisha Rahman"),
            P::new("PERSON", "Carlos Mendes", "Carlos Mendes signed off on the revised budget"),
            P::new("PERSON", "Ingrid Larsson", "route the escalation to Ingrid Larsson tonight"),
            // --- Widened ML-unique LOCATION corpus ------------------------------
            P::new("LOCATION", "Reykjavik", "the working group convenes in Reykjavik next month"),
            P::new("LOCATION", "Kyoto", "the new materials lab opened in Kyoto this spring"),
            P::new("LOCATION", "Lagos", "the regional hub was consolidated into Lagos"),
            P::new("LOCATION", "Geneva", "the arbitration hearing resumed in Geneva yesterday"),
            P::new("LOCATION", "Mumbai", "the consignment cleared customs in Mumbai overnight"),
            P::new("LOCATION", "Nairobi", "the field survey team is now based in Nairobi"),
        ]
    }

    /// All fixtures, keyed by a stable fixture id, each with its own positive list.
    /// Short fixtures hold one needle; long fixtures hold several embedded needles.
    struct Fixture {
        id: String,
        text: String,
        needles: Vec<(&'static str, &'static str)>, // (kind, needle)
    }

    /// Full gate corpus. When `ml_only`, keep only fixtures carrying at least one
    /// ML-owned needle (PERSON/LOCATION) — a smaller, faster set for iterating on
    /// model-numeric changes. The long-doc fixtures are retained either way because
    /// they hold the long-`T` PERSON/LOCATION spans that f16/Q8/P1 break first.
    fn corpus_filtered(ml_only: bool) -> Vec<Fixture> {
        let all = corpus();
        if !ml_only {
            return all;
        }
        all.into_iter()
            .filter(|f| f.needles.iter().any(|(kind, _)| ml_owned(kind)))
            .collect()
    }

    fn corpus() -> Vec<Fixture> {
        let mut fixtures: Vec<Fixture> = short_positives()
            .into_iter()
            .enumerate()
            .map(|(i, p)| Fixture {
                id: format!("short-{i:02}-{}", p.kind),
                text: p.text.to_string(),
                needles: vec![(p.kind, p.needle)],
            })
            .collect();

        // Long-doc #1: PERSON + EMAIL + PHONE embedded in long prose.
        let n1: Vec<(&'static str, &'static str)> = vec![
            ("PERSON", "Jonathan Mercer"),
            ("EMAIL_ADDRESS", "j.mercer@northwind-logistics.com"),
            ("PHONE_NUMBER", "+1 312 555 0177"),
        ];
        let n1_sentences: &[(&'static str, &'static str)] = &[
            (
                "PERSON",
                "The review was chaired by Jonathan Mercer, who summarized the findings.",
            ),
            (
                "EMAIL_ADDRESS",
                "Follow-up questions should be sent to j.mercer@northwind-logistics.com directly.",
            ),
            (
                "PHONE_NUMBER",
                "He can be reached by phone at +1 312 555 0177 during business hours.",
            ),
        ];
        fixtures.push(Fixture {
            id: "long-00-ops-review".to_string(),
            text: long_doc(n1_sentences, "OPERATIONS REVIEW MEMORANDUM."),
            needles: n1,
        });

        // Long-doc #2: PERSON + LOCATION + CREDIT_CARD embedded in long prose.
        let n2: Vec<(&'static str, &'static str)> = vec![
            ("PERSON", "Priya Nair"),
            ("LOCATION", "Rotterdam"),
            ("CREDIT_CARD", "4111111111111111"),
        ];
        let n2_sentences: &[(&'static str, &'static str)] = &[
            (
                "PERSON",
                "Account management for this region is led by Priya Nair this quarter.",
            ),
            (
                "LOCATION",
                "The primary transshipment hub remains the port of Rotterdam for now.",
            ),
            (
                "CREDIT_CARD",
                "An expense was charged to corporate card 4111111111111111 in error and reversed.",
            ),
        ];
        fixtures.push(Fixture {
            id: "long-01-logistics".to_string(),
            text: long_doc(n2_sentences, "ANNUAL LOGISTICS SUMMARY."),
            needles: n2,
        });

        // Long-doc #3: two PERSONs + LOCATION in long prose — extra long-`T`
        // ML-owned coverage (the spans low-precision/banded paths break first),
        // with two distinct persons in one document.
        let n3: Vec<(&'static str, &'static str)> = vec![
            ("PERSON", "Helena Voss"),
            ("PERSON", "Tomás Herrera"),
            ("LOCATION", "Reykjavik"),
        ];
        let n3_sentences: &[(&'static str, &'static str)] = &[
            (
                "PERSON",
                "The compliance brief was prepared by Helena Voss for the board.",
            ),
            (
                "PERSON",
                "Field operations for the quarter were coordinated by Tomás Herrera.",
            ),
            (
                "LOCATION",
                "The contingency site selected for the program is Reykjavik.",
            ),
        ];
        fixtures.push(Fixture {
            id: "long-02-compliance".to_string(),
            text: long_doc(n3_sentences, "QUARTERLY COMPLIANCE BRIEF."),
            needles: n3,
        });

        fixtures
    }

    // ---------------------------------------------------------------------------
    // Engine + scoring
    // ---------------------------------------------------------------------------

    /// True iff this host has the AVX512-BF16 ISA the native `Bf16Vnni` kernel needs.
    /// Mirrors presidio's `has_avx512_bf16`; the gate checks independently so it can
    /// REFUSE to certify Bf16Vnni on a host where it would silently fall back to the
    /// safe kernel (a fallback run must never masquerade as a Bf16Vnni recall proof).
    fn host_has_avx512_bf16() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bf16")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Build a Strict-profile engine with the ML recognizer loaded synchronously.
    /// Returns the engine and the recognizer handle (for direct scoring) on success.
    ///
    /// `baseline=true` (for `--dump-golden`) forces the canonical **F32 / None / dense
    /// oracle**, ignoring env — that is the reference truth the golden records.
    /// `baseline=false` (for `--check-golden`) builds the **SHIPPED DEFAULTS**
    /// (Bf16 + banded) so a *bare* gate run validates what production actually runs;
    /// env vars then override a single lever to measure it against the F32 golden:
    ///   `SORDINO_ML_QUANT`     = none|bf16|bf16_vnni|q8_0  (default: bf16, shipped)
    ///   `SORDINO_ML_BANDED`    = 0/1                       (default: 1, shipped)
    ///   `SORDINO_ML_PRECISION` = f32|f16                   (default: f32)
    fn build_engine_with_ml(
        baseline: bool,
    ) -> Result<(MaskEngine, std::sync::Arc<dyn MlRecognizer>), String> {
        let mut cfg = EngineConfig::for_profile(Profile::Strict);
        let (precision, quant, banded) = if baseline {
            // The golden oracle: always F32 / None / dense, independent of env.
            (
                sordino_engine::ComputePrecision::F32,
                sordino_engine::Quantization::None,
                false,
            )
        } else {
            let precision = match std::env::var("SORDINO_ML_PRECISION").ok().as_deref() {
                Some("f16") | Some("F16") => sordino_engine::ComputePrecision::F16,
                _ => sordino_engine::ComputePrecision::F32,
            };
            // Default to the SHIPPED quant (Bf16); explicit values select a lever
            // (`none`/`f32` forces the F32 path to reproduce the golden via check).
            let quant = match std::env::var("SORDINO_ML_QUANT").ok().as_deref() {
                Some("none") | Some("None") | Some("f32") => sordino_engine::Quantization::None,
                Some("q8_0") | Some("Q8_0") | Some("q8") => sordino_engine::Quantization::Q8_0,
                Some("bf16") | Some("BF16") => sordino_engine::Quantization::Bf16,
                Some("bf16_vnni") | Some("bf16vnni") | Some("vnni") => {
                    sordino_engine::Quantization::Bf16Vnni
                }
                _ => sordino_engine::Quantization::Bf16, // shipped default
            };
            // Default to the SHIPPED banded=true; explicit 0/false/off forces dense.
            let banded = !matches!(
                std::env::var("SORDINO_ML_BANDED").ok().as_deref(),
                Some("0") | Some("false") | Some("off")
            );
            (precision, quant, banded)
        };

        // Refuse to certify the native VNNI kernel on a host that will silently fall
        // back to the safe (recall-neutral) bf16 kernel: the gate would report a
        // PASS for Bf16Vnni without ever exercising the recall-RISK vdpbf16ps path
        // that rounds activations (audit privacy #1). Fail loudly instead.
        if matches!(quant, sordino_engine::Quantization::Bf16Vnni) && !host_has_avx512_bf16() {
            return Err(
                "SORDINO_ML_QUANT=bf16_vnni requested, but this host lacks AVX512-BF16 — the \
                 native vdpbf16ps kernel would silently fall back to the safe bf16 kernel. \
                 Refusing to certify a Bf16Vnni recall result that did not run the risky path."
                    .to_string(),
            );
        }

        cfg.ml = MlConfig {
            enabled: true,
            model: "openai/privacy-filter".to_string(),
            compute_precision: precision,
            quant,
            banded_attention: banded,
            ..Default::default()
        };
        eprintln!(
            "[{}] compute_precision={precision:?} quant={quant:?} banded_attention={banded}",
            if baseline {
                "dump: F32 oracle"
            } else {
                "check: shipped defaults (env overrides one lever vs the F32 golden)"
            }
        );

        let engine = MaskEngine::new(cfg.clone()).map_err(|e| format!("build engine: {e}"))?;

        // Load the (cached) model synchronously and install it into the engine's hot
        // slot, mirroring the proxy's ml_begin_load -> build_recognizer -> ml_set_ready
        // sequence but on this thread.
        eprintln!("loading openai/privacy-filter (cached) ...");
        let t0 = Instant::now();
        let rec = sordino_engine::ml::build_recognizer(&cfg.ml)
            .map_err(|e| format!("build_recognizer: {e}"))?;
        let generation = engine.ml_begin_load(cfg.ml.clone());
        engine.ml_set_ready(generation, rec.clone());
        eprintln!(
            "model ready in {:?}; ml_active={}",
            t0.elapsed(),
            engine.ml_active()
        );
        if !engine.ml_active() {
            return Err("model installed but engine reports ml inactive".to_string());
        }
        Ok((engine, rec))
    }

    /// Did `mask()` mask the needle? (manifest entry of expected kind overlapping the
    /// needle, OR needle removed verbatim from the masked text). Same acceptance as
    /// `profile_bench::masked_expected`.
    fn masked_expected(
        out: &sordino_engine::MaskOutcome,
        kind: &str,
        needle: &str,
        original: &str,
    ) -> bool {
        let by_manifest = out.manifest.entries.iter().any(|e| {
            e.entity_kind == kind
                && (e.canonical_form.contains(needle) || needle.contains(&e.canonical_form))
        });
        if by_manifest {
            return true;
        }
        original.contains(needle) && !out.masked_text.contains(needle)
    }

    /// Best recognizer score for a result whose span overlaps the needle's byte range
    /// in `text` and whose entity kind matches `kind`. `None` if the ML recognizer
    /// produced no overlapping match (the regex-only spans legitimately have no ML
    /// score — recorded as null and excluded from score-drift checks).
    fn ml_score_for(rec: &dyn MlRecognizer, text: &str, kind: &str, needle: &str) -> Option<f32> {
        let nstart = text.find(needle)?;
        let nend = nstart + needle.len();
        let results = rec.analyze(text).unwrap_or_default();
        let mut best: Option<f32> = None;
        for r in &results {
            let overlaps = r.start < nend && r.end > nstart;
            if overlaps && r.entity_type.to_string() == kind {
                best = Some(best.map_or(r.score, |b| b.max(r.score)));
            }
        }
        best
    }

    /// Per-needle observation.
    #[derive(Clone)]
    struct Obs {
        needle: String,
        kind: String,
        hit: bool,
        score: Option<f32>,
    }

    /// Run the corpus once; collect per-fixture observations and total mask() wall time.
    fn run_once(
        engine: &MaskEngine,
        rec: &dyn MlRecognizer,
        fixtures: &[Fixture],
    ) -> (BTreeMap<String, Vec<Obs>>, u128) {
        let mut per_fixture: BTreeMap<String, Vec<Obs>> = BTreeMap::new();
        let mut total_ns: u128 = 0;
        for f in fixtures {
            let t0 = Instant::now();
            let out = engine.mask(&f.text, Surface::UserMessage).expect("mask");
            total_ns += t0.elapsed().as_nanos();
            let obs: Vec<Obs> = f
                .needles
                .iter()
                .map(|(kind, needle)| Obs {
                    needle: needle.to_string(),
                    kind: kind.to_string(),
                    hit: masked_expected(&out, kind, needle, &f.text),
                    score: ml_score_for(rec, &f.text, kind, needle),
                })
                .collect();
            per_fixture.insert(f.id.clone(), obs);
        }
        (per_fixture, total_ns)
    }

    // ---------------------------------------------------------------------------
    // Golden snapshot I/O
    // ---------------------------------------------------------------------------

    fn obs_to_json(obs: &[Obs]) -> Value {
        Value::Array(
            obs.iter()
                .map(|o| {
                    json!({
                        "needle": o.needle,
                        "kind": o.kind,
                        "hit": o.hit,
                        "score": o.score,
                    })
                })
                .collect(),
        )
    }

    fn recall_counts(per_fixture: &BTreeMap<String, Vec<Obs>>) -> (usize, usize) {
        let mut hit = 0;
        let mut total = 0;
        for obs in per_fixture.values() {
            for o in obs {
                total += 1;
                if o.hit {
                    hit += 1;
                }
            }
        }
        (hit, total)
    }

    // ---------------------------------------------------------------------------
    // ML-only recall
    //
    // The end-to-end `hit` counts a needle as covered if ANY recognizer masked it.
    // That is the right top-line privacy number (recall == privacy == what egresses)
    // but it is the WRONG lens for gating an ML-code change: structured PII
    // (EMAIL/PHONE/CREDIT_CARD/keys/IP) is regex's job and forms a constant floor
    // that masks ML regressions. f16 proved it — it zeroed the model's entire PERSON
    // contribution, yet end-to-end recall only fell 26→22 because regex held the
    // rest. So we ALSO track an isolated ML metric: over the ML-owned kinds only,
    // count what the ML recognizer ITSELF detected (via its own `analyze()` score),
    // which regex/context cannot inflate. ML changes gate on THIS number.
    // ---------------------------------------------------------------------------

    /// Kinds the ML model is solely responsible for under this corpus. Everything
    /// else is regex/context-detectable and excluded from the ML metric.
    const ML_OWNED_KINDS: &[&str] = &["PERSON", "LOCATION"];

    fn ml_owned(kind: &str) -> bool {
        ML_OWNED_KINDS.contains(&kind)
    }

    /// Score a span must clear to count as a real ML detection. Mirrors the
    /// engine's default `min_score` (0.5): a span the recognizer scores below this
    /// would not survive into the manifest on the model's own merit, so it is not
    /// an ML "hit" for gating purposes.
    const ML_SCORE_THRESHOLD: f32 = 0.5;

    /// Did the ML recognizer detect this ML-owned needle at/above threshold? `score`
    /// comes from `ml_score_for` (a direct `rec.analyze()` call), so this is the
    /// model's own verdict, independent of regex/context.
    fn ml_detected_score(kind: &str, score: Option<f32>) -> bool {
        ml_owned(kind) && score.is_some_and(|s| s >= ML_SCORE_THRESHOLD)
    }

    /// ML-only recall over the live observations: (detected, total) across ML-owned
    /// needles. A drop here is a model regression the end-to-end number can hide.
    fn ml_recall_counts(per_fixture: &BTreeMap<String, Vec<Obs>>) -> (usize, usize) {
        let mut hit = 0;
        let mut total = 0;
        for obs in per_fixture.values() {
            for o in obs {
                if ml_owned(&o.kind) {
                    total += 1;
                    if ml_detected_score(&o.kind, o.score) {
                        hit += 1;
                    }
                }
            }
        }
        (hit, total)
    }

    /// Median wall time (ms) of a full corpus pass through the ML recognizer's
    /// `analyze()`, over `reps` (>=3) reps.
    ///
    /// We time `rec.analyze()` directly, NOT `engine.mask()`: `mask()` memoizes
    /// detections in a per-text cache (keyed on `text_hash`), so repeated reps on
    /// identical fixtures would measure cache hits (~0ms), not inference. The CPU
    /// optimization work (f16/Q8/P1, attention/MoE kernels) lives entirely inside
    /// the recognizer's inference path, so timing `analyze()` is both cache-immune
    /// and the faithful measure of exactly what those levers change.
    fn timed_total_ms(rec: &dyn MlRecognizer, fixtures: &[Fixture], reps: usize) -> f64 {
        let mut samples: Vec<f64> = Vec::with_capacity(reps);
        for _ in 0..reps.max(3) {
            let t0 = Instant::now();
            for f in fixtures {
                let _ = rec.analyze(&f.text);
            }
            samples.push(t0.elapsed().as_nanos() as f64 / 1.0e6);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        samples[samples.len() / 2]
    }

    fn dump_golden(path: &str) -> ExitCode {
        // The golden is the canonical F32/None/dense oracle (baseline=true).
        let (engine, rec) = match build_engine_with_ml(true) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("FATAL: {e}");
                return ExitCode::from(2);
            }
        };
        // Golden is always the FULL corpus; subset (`--ml-only`) runs compare a
        // subset of fixtures against this same golden.
        let fixtures = corpus();

        // One observation pass for the recorded hit/score state.
        let (per_fixture, _ns) = run_once(&engine, rec.as_ref(), &fixtures);
        let (hit, total) = recall_counts(&per_fixture);
        let (ml_hit, ml_total) = ml_recall_counts(&per_fixture);

        if total == 0 || hit == 0 {
            eprintln!(
                "FATAL: implausible recall {hit}/{total} — model likely not loaded; refusing to write golden"
            );
            return ExitCode::from(2);
        }
        if ml_total == 0 || ml_hit == 0 {
            eprintln!(
                "FATAL: implausible ML-only recall {ml_hit}/{ml_total} — the ML model contributed \
                 nothing (broken model path?); refusing to write golden"
            );
            return ExitCode::from(2);
        }

        // Timed reps for perf baseline.
        let total_ms = timed_total_ms(rec.as_ref(), &fixtures, 3);

        let mut fixtures_json = serde_json::Map::new();
        for (id, obs) in &per_fixture {
            fixtures_json.insert(id.clone(), obs_to_json(obs));
        }

        let golden = json!({
            "schema": "ml_gate.golden.v1",
            "model": "openai/privacy-filter",
            "profile": "Strict",
            "n_fixtures": fixtures.len(),
            "recall": { "hit": hit, "total": total },
            "ml_recall": { "hit": ml_hit, "total": ml_total },
            "total_ms": total_ms,
            "reps": 3,
            "fixtures": Value::Object(fixtures_json),
        });

        let s = serde_json::to_string_pretty(&golden).expect("serialize golden");
        if let Err(e) = std::fs::write(path, s) {
            eprintln!("FATAL: write golden {path}: {e}");
            return ExitCode::from(2);
        }

        println!("== ml_gate: golden written ==");
        println!("path:       {path}");
        println!("n_fixtures: {}", fixtures.len());
        println!("recall:     {hit}/{total} (end-to-end, regex+context+ML)");
        println!("ml_recall:  {ml_hit}/{ml_total} (ML-owned spans, model only)");
        println!("total_ms:   {total_ms:.2} (median of >=3 reps)");
        ExitCode::SUCCESS
    }

    fn check_golden(path: &str, tol: f32, ml_only: bool) -> ExitCode {
        let golden: Value = match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("FATAL: parse golden {path}: {e}");
                    return ExitCode::from(2);
                }
            },
            Err(e) => {
                eprintln!("FATAL: read golden {path}: {e}");
                return ExitCode::from(2);
            }
        };

        // Check the SHIPPED defaults (Bf16 + banded) against the F32 golden
        // (baseline=false); env vars override a single lever. A bare
        // `--check-golden` therefore validates exactly what production runs.
        let (engine, rec) = match build_engine_with_ml(false) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("FATAL: {e}");
                return ExitCode::from(2);
            }
        };
        let fixtures = corpus_filtered(ml_only);
        let (per_fixture, _ns) = run_once(&engine, rec.as_ref(), &fixtures);
        let (now_hit, now_total) = recall_counts(&per_fixture);
        let (now_ml_hit, now_ml_total) = ml_recall_counts(&per_fixture);
        let now_ms = timed_total_ms(rec.as_ref(), &fixtures, 3);

        let g_fixtures = golden.get("fixtures").and_then(|v| v.as_object());
        let g_ms = golden
            .get("total_ms")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let mut fail = false;
        let mut dropped: Vec<String> = Vec::new();
        let mut dropped_ml: Vec<String> = Vec::new();
        let mut score_flags: Vec<String> = Vec::new();
        // Golden recalls recomputed over the fixtures actually present in THIS run,
        // so an `--ml-only` subset compares apples-to-apples against the full golden.
        let (mut g_hit, mut g_total) = (0usize, 0usize);
        let (mut g_ml_hit, mut g_ml_total) = (0usize, 0usize);

        if let Some(gf) = g_fixtures {
            for (id, obs) in &per_fixture {
                let g_obs = gf.get(id).and_then(|v| v.as_array());
                let Some(g_obs) = g_obs else {
                    eprintln!(
                        "WARN: fixture {id} present now but absent in golden (corpus changed)"
                    );
                    continue;
                };
                for o in obs {
                    // match golden entry by (needle, kind)
                    let g = g_obs.iter().find(|gv| {
                        gv.get("needle").and_then(|v| v.as_str()) == Some(o.needle.as_str())
                            && gv.get("kind").and_then(|v| v.as_str()) == Some(o.kind.as_str())
                    });
                    let Some(g) = g else {
                        eprintln!(
                            "WARN: needle {:?} ({}) in {id} absent in golden",
                            o.needle, o.kind
                        );
                        continue;
                    };
                    let g_hit_b = g.get("hit").and_then(|v| v.as_bool()).unwrap_or(false);
                    let g_score = g.get("score").and_then(|v| v.as_f64()).map(|x| x as f32);

                    // End-to-end accounting (present-fixture golden vs now).
                    g_total += 1;
                    if g_hit_b {
                        g_hit += 1;
                    }
                    // DROPPED TRUE POSITIVE (end-to-end): hit in golden, miss now.
                    if g_hit_b && !o.hit {
                        fail = true;
                        dropped.push(format!("[{id}] {} ({})", o.needle, o.kind));
                    }

                    // ML-only accounting over ML-owned needles, using the model's
                    // own score — regex/context cannot mask a regression here.
                    if ml_owned(&o.kind) {
                        let g_ml = ml_detected_score(&o.kind, g_score);
                        let n_ml = ml_detected_score(&o.kind, o.score);
                        g_ml_total += 1;
                        if g_ml {
                            g_ml_hit += 1;
                        }
                        if g_ml && !n_ml {
                            fail = true;
                            dropped_ml.push(format!(
                                "[{id}] {} ({}): golden score {} now {}",
                                o.needle,
                                o.kind,
                                g_score.map_or("none".into(), |s| format!("{s:.4}")),
                                o.score.map_or("none".into(), |s| format!("{s:.4}")),
                            ));
                        }
                    }

                    // Score drift.
                    if let (Some(gs), Some(ns)) = (g_score, o.score) {
                        let d = (gs - ns).abs();
                        if d > tol {
                            score_flags.push(format!(
                            "[{id}] {} ({}): golden {:.4} now {:.4} (|delta| {:.4} > tol {:.4})",
                            o.needle, o.kind, gs, ns, d, tol
                        ));
                        }
                    }
                }
            }
        } else {
            eprintln!("WARN: golden has no fixtures map");
        }

        // Recall regression — either metric dropping is a FAIL.
        if now_hit < g_hit || now_ml_hit < g_ml_hit {
            fail = true;
        }

        println!("== ml_gate: check vs golden ==");
        println!("golden:  {path}");
        if ml_only {
            println!("mode:    ML-ONLY subset ({} fixtures)", fixtures.len());
        }
        println!(
            "recall:    now {now_hit}/{now_total} vs golden {g_hit}/{g_total} (end-to-end, regex+context+ML)"
        );
        println!(
            "ml_recall: now {now_ml_hit}/{now_ml_total} vs golden {g_ml_hit}/{g_ml_total} (ML-owned spans, model only)"
        );
        let ratio = if g_ms > 0.0 { now_ms / g_ms } else { f64::NAN };
        println!("timing:  now {now_ms:.2}ms vs golden {g_ms:.2}ms (ratio {ratio:.3})");

        if dropped.is_empty() {
            println!("dropped true-positives (end-to-end): NONE");
        } else {
            println!("dropped true-positives (end-to-end) ({}):", dropped.len());
            for d in &dropped {
                println!("  DROP {d}");
            }
        }

        if dropped_ml.is_empty() {
            println!("dropped ML detections (model-only): NONE");
        } else {
            println!("dropped ML detections (model-only) ({}):", dropped_ml.len());
            for d in &dropped_ml {
                println!("  ML-DROP {d}");
            }
        }

        if score_flags.is_empty() {
            println!("score deltas > tol ({tol:.4}): NONE");
        } else {
            println!("score deltas > tol ({tol:.4}) [{}]:", score_flags.len());
            for s in &score_flags {
                println!("  DRIFT {s}");
            }
        }

        if fail {
            println!("\nRESULT: FAIL");
            ExitCode::from(1)
        } else {
            println!("\nRESULT: PASS");
            ExitCode::SUCCESS
        }
    }

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        let mut mode: Option<(&str, String)> = None;
        let mut tol: f32 = 1e-3;
        let mut ml_only = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--dump-golden" => {
                    let p = args.get(i + 1).cloned().unwrap_or_default();
                    mode = Some(("dump", p));
                    i += 2;
                }
                "--check-golden" => {
                    let p = args.get(i + 1).cloned().unwrap_or_default();
                    mode = Some(("check", p));
                    i += 2;
                }
                "--tol" => {
                    if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<f32>().ok()) {
                        tol = v;
                    }
                    i += 2;
                }
                // Fast iteration: run only the ML-owned fixtures (PERSON/LOCATION)
                // and gate on the ML-only recall. Skips the regex-only structured-PII
                // fixtures that the model is not responsible for.
                "--ml-only" => {
                    ml_only = true;
                    i += 1;
                }
                other => {
                    eprintln!("unknown arg: {other}");
                    i += 1;
                }
            }
        }

        match mode {
            Some(("dump", p)) if !p.is_empty() => dump_golden(&p),
            Some(("check", p)) if !p.is_empty() => check_golden(&p, tol, ml_only),
            _ => {
                eprintln!("usage:");
                eprintln!("  ml_gate --dump-golden <path>");
                eprintln!("  ml_gate --check-golden <path> [--tol <f>] [--ml-only]");
                ExitCode::from(2)
            }
        }
    }
} // mod ml_gate_impl

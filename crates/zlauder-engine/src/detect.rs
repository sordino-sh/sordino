//! Detection: presidio analyzer + custom rules, filtered and overlap-resolved
//! into a sorted, non-overlapping span list with a resolved operator each.

use presidio_analyzer::recognizers::GENERIC_ENTROPY_PATTERN;
use presidio_analyzer::{AnalyzeRequest, AnalyzerEngine};
use presidio_core::{NlpArtifacts, Recognizer, RecognizerResult, Token};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;

use crate::cache::{CachedDetection, Source};
use crate::config::{CustomReplacement, EngineConfig, Operator};
use crate::error::EngineError;
use crate::surface::Surface;

/// Identity of the bundled (compiled-in) regex/custom recognizer set. Folded into
/// `policy_fp` (audit #1) so a change to the detection code abandons stale cache
/// entries — both the in-memory cache (belt-and-suspenders: a new binary already
/// starts with an empty cache) and any future on-disk backend. BUMP THIS whenever
/// the presidio recognizer set or this module's detection logic changes in a way
/// that alters output for unchanged input.
// v2: fixed the Category entity strings that used parse aliases instead of canonical
// `EntityType` Display names (IBAN_CODE / CRYPTO / MEDICAL_LICENSE / ABA_ROUTING_NUMBER),
// which had been silently dropping those detections at the category gate. This changes
// detection output for unchanged text, so the bump invalidates stale cache entries.
// v3: added the defense-in-depth precision gate on presidio's generic high-entropy
// API_KEY catch-all (see `plausible_generic_secret`) — drops 32+-char file paths,
// identifiers, and hex/UUID digests that the 0.55 catch-all can't distinguish from a
// real opaque key. Changes output for unchanged text, so bump to abandon stale cache.
// v4: wired presidio's LemmaContextAwareEnhancer (context words boost nearby matches,
// e.g. "call"/"number" lift a PHONE_NUMBER from its 0.4 base over the 0.5 floor). The
// regex pass now runs with NLP artifacts and a lowered pre-enhancement floor, so
// context-bearing text yields detections it didn't before — bump to abandon stale cache.
// v5: context-free PHONE_NUMBER tie-break — a phone still at exactly the un-boosted
// `PHONE_BASE_SCORE` (0.4, no context word) is dropped in `ingest_results`, so a
// phone-shaped order/id number no longer false-positives at the Strict 0.4 floor.
// Changes detection output for unchanged text (a context-free phone that previously
// masked at a ≤0.4 floor no longer does) — bump to abandon stale cache.
pub const DETECTOR_VERSION: u64 = 5;

/// Score the [`LemmaContextAwareEnhancer`] adds when a recognizer's context word
/// is found near a match (mirrors `LemmaContextAwareEnhancer::new`'s
/// `context_similarity_factor`). The regex pass is pre-filtered to
/// `score_threshold - CONTEXT_BOOST` so any candidate a context word could lift
/// over the floor survives presidio's filter-before-enhance step; the authoritative
/// `score_threshold` gate is then re-applied in `ingest_results` on the boosted score.
const CONTEXT_BOOST: f32 = 0.35;

/// The flat base score presidio's `PhoneRecognizer` assigns to EVERY
/// libphonenumber-valid candidate (mirrors `PHONE_SCORE` in
/// `presidio-analyzer`'s `phone.rs`). A PHONE_NUMBER detection still sitting at
/// exactly this value was NOT lifted by the context enhancer (which only ever adds
/// `CONTEXT_BOOST`), i.e. it is context-free — the order-number / id-number
/// false-positive shape. Used by `ingest_results` to drop the context-free phone
/// tie that the Strict 0.4 floor would otherwise mask. Kept in lock-step with the
/// upstream constant via `phone_base_score_matches_upstream` below.
const PHONE_BASE_SCORE: f32 = 0.4;

/// A custom rule compiled to a regex (literal rules are escaped). Matching via
/// regex on the original text gives correct byte offsets for any case folding.
#[derive(Clone)]
pub struct CompiledCustom {
    re: Regex,
    pub entity_type: String,
    pub literal_token: bool,
    pub token: Option<String>,
    pub priority: u32,
    pub surfaces: Option<HashSet<Surface>>,
}

pub fn compile_customs(rules: &[CustomReplacement]) -> Result<Vec<CompiledCustom>, EngineError> {
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let raw = if r.is_regex {
            r.pattern.clone()
        } else {
            regex::escape(&r.pattern)
        };
        let re = RegexBuilder::new(&raw)
            .case_insensitive(!r.case_sensitive)
            .build()
            .map_err(|source| EngineError::BadCustomRegex {
                pattern: r.pattern.clone(),
                source,
            })?;
        out.push(CompiledCustom {
            re,
            entity_type: r.entity_type.clone(),
            literal_token: r.literal_token,
            token: r.token.clone(),
            priority: r.priority,
            surfaces: r.apply_to_surfaces.clone(),
        });
    }
    // Lower `priority` value = higher precedence; apply those first.
    out.sort_by_key(|c| c.priority);
    Ok(out)
}

/// Resolve the apply-time operator for a (cached) detection from the LIVE policy
/// config (audit #4): operators are NOT cached, so a per-type override / default
/// change applies on the next mask with no detection re-run. A `literal_token`
/// custom is always `Token` (a structural property of the rule, captured in
/// `det.literal`); everything else follows `operator_for`.
pub fn resolve_operator(cfg: &EngineConfig, det: &CachedDetection) -> Operator {
    if det.literal {
        Operator::Token
    } else {
        cfg.operator_for(&det.entity_type)
    }
}

pub fn run_detection(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    ml: Option<&dyn Recognizer>,
    text: &str,
    surface: Surface,
) -> Result<Vec<CachedDetection>, EngineError> {
    let mut dets: Vec<CachedDetection> = Vec::new();
    // Spans of allow-listed values; any detection fully contained in one of these
    // is also suppressed (allow-listing "admin@example.com" covers its
    // "example.com" sub-domain too).
    let mut allowed_spans: Vec<(usize, usize)> = Vec::new();

    // Pass 1: custom rules (already priority-sorted).
    for c in customs {
        if let Some(surfs) = &c.surfaces
            && !surfs.contains(&surface)
        {
            continue;
        }
        for m in c.re.find_iter(text) {
            let slice = &text[m.start()..m.end()];
            if cfg.allow_list.is_allowed(slice) {
                allowed_spans.push((m.start(), m.end()));
                continue;
            }
            // Operator is resolved at APPLY time (see `resolve_operator`); we record
            // only the structural `literal` marker + the fixed token here.
            dets.push(CachedDetection {
                start: m.start(),
                end: m.end(),
                entity_type: c.entity_type.clone(),
                score: 1.0,
                source: Source::Custom,
                literal: c.literal_token,
                fixed_token: if c.literal_token {
                    c.token.clone()
                } else {
                    None
                },
            });
        }
    }

    // Pass 2: presidio regex analyzer, with context-aware enhancement.
    //
    // The enhancer needs NLP artifacts (tokens + lemmas) to find context words near
    // a match; the regex path has no NLP engine, so we build lightweight artifacts
    // here. presidio filters by threshold BEFORE enhancing, so we pre-filter at
    // `score_threshold - CONTEXT_BOOST` — low enough that a boostable candidate
    // (e.g. a phone at 0.4) survives to be enhanced — and let `ingest_results`
    // re-apply the authoritative `score_threshold` to the boosted score.
    let artifacts = context_artifacts(text, &cfg.language);
    let pre_floor = (cfg.score_threshold - CONTEXT_BOOST).max(0.0);
    let results = analyzer.analyze(
        AnalyzeRequest::new(text, &cfg.language)
            .nlp_artifacts(&artifacts)
            .score_threshold(pre_floor),
    );
    ingest_results(
        results,
        cfg,
        text,
        &mut dets,
        &mut allowed_spans,
        Source::Regex,
    );

    // Pass 2b: the optional ML recognizer (openai/privacy-filter), if loaded. It
    // returns the same `RecognizerResult` type, so it flows through the identical
    // category gate / allow-list / overlap dedup below — e.g. its PERSON/LOCATION
    // spans only mask when the `personal` category is on. Tagged `Source::Ml` so the
    // deferred Component-3 burn can single it out.
    if let Some(rec) = ml {
        let ml_results = rec.analyze(text, None, None);
        ingest_results(
            ml_results,
            cfg,
            text,
            &mut dets,
            &mut allowed_spans,
            Source::Ml,
        );
    }

    // Suppress detections fully contained within an allow-listed span.
    if !allowed_spans.is_empty() {
        dets.retain(|d| {
            !allowed_spans
                .iter()
                .any(|(s, e)| *s <= d.start && d.end <= *e)
        });
    }

    Ok(resolve_overlaps(dets))
}

/// Build lightweight NLP artifacts for the context-aware enhancer.
///
/// The enhancer only needs word tokens (with byte offsets) and parallel lemmas to
/// test whether a recognizer's context word (e.g. "call", "phone") sits within the
/// window before a match. We don't have — or need — a real lemmatizer/NER here: a
/// match against lowercased word runs catches the literal context words recognizers
/// declare. Tokens are maximal Unicode alphanumeric runs; punctuation/whitespace are
/// boundaries (and never emitted), so byte offsets stay correct across multibyte text.
fn context_artifacts(text: &str, language: &str) -> NlpArtifacts {
    let mut artifacts = NlpArtifacts::new(language);
    let mut start: Option<usize> = None;
    for (idx, ch) in text.char_indices() {
        if ch.is_alphanumeric() {
            start.get_or_insert(idx);
        } else if let Some(s) = start.take() {
            push_word(&mut artifacts, &text[s..idx], s, idx);
        }
    }
    if let Some(s) = start.take() {
        push_word(&mut artifacts, &text[s..], s, text.len());
    }
    artifacts
}

fn push_word(artifacts: &mut NlpArtifacts, word: &str, start: usize, end: usize) {
    artifacts.tokens.push(Token::new(word, start, end));
    artifacts.lemmas.push(word.to_lowercase());
}

/// Filter one recognizer's results through the engine policy and push survivors to
/// `dets` (allow-listed values are recorded as suppression spans instead). Shared
/// by the regex analyzer (Pass 2) and the ML recognizer (Pass 2b) so both get
/// identical category-gate / allow-list / operator treatment.
fn ingest_results(
    results: Vec<RecognizerResult>,
    cfg: &EngineConfig,
    text: &str,
    dets: &mut Vec<CachedDetection>,
    allowed_spans: &mut Vec<(usize, usize)>,
    source: Source,
) {
    for r in results {
        // One predictable score floor across both sources, and the authoritative
        // gate: the regex analyzer ran with a lowered pre-enhancement floor (so the
        // context enhancer could boost candidates), and the ML recognizer applies its
        // own `min_score` — so re-applying `score_threshold` here, on the final
        // (possibly context-boosted) score, keeps the engine-wide floor authoritative.
        if r.score < cfg.score_threshold {
            continue;
        }
        // Targeted precision gate for the context-free PHONE_NUMBER tie. The phone
        // recognizer assigns EVERY libphonenumber-valid candidate the same flat base
        // score (`PHONE_SCORE` = 0.4); the context enhancer only ever LIFTS that base
        // (+`CONTEXT_BOOST` → 0.75) when a context word ("call"/"number"/…) sits near
        // the match. So a PHONE_NUMBER still AT exactly the 0.4 base is, by definition,
        // context-free — a phone-shaped run with no phone context, which is the
        // order-number / id-number false-positive shape (e.g. "Order #4021558"). At the
        // Strict profile the floor (0.4) ties that base, so the plain `<` gate above
        // lets the bare run through. Drop a PHONE_NUMBER whose score is still exactly the
        // un-boosted base: a real phone in prose almost always carries a context word
        // (so it was boosted to 0.75 and is unaffected), while a context-free number is
        // ambiguous enough that masking it is a net false positive. This is scoped to
        // PHONE_NUMBER only, so SSN/email/card/secret detections at their own floors are
        // untouched. (Documented tradeoff: a genuinely context-free phone needs ML or an
        // explicit per-entity operator to mask — same lever the enhancer doc names.)
        let entity_type = r.entity_type.to_string();
        if entity_type == "PHONE_NUMBER" && r.score <= PHONE_BASE_SCORE {
            continue;
        }
        if !cfg.entity_enabled(&entity_type) {
            continue;
        }
        let Some(slice) = r.text(text) else {
            continue;
        };
        if slice.is_empty() {
            continue;
        }
        // Defense-in-depth precision gate, scoped to presidio's generic high-entropy
        // API_KEY catch-all (`pattern_name == GENERIC_ENTROPY_PATTERN`, score ~0.55).
        // zlauder masks a code-heavy traffic domain where 32+-char file paths, hashed
        // asset names, hex digests, and long identifiers are everywhere — exactly what
        // that catch-all cannot tell apart from an opaque key. We re-apply presidio's
        // own structural gate here so zlauder stays correct even when built against a
        // presidio predating the upstream fix (local override / older pinned rev);
        // against a fixed presidio the implausible hits never arrive, so this is a
        // no-op. The 150+ prefix-anchored / context-gated service patterns carry a
        // different `pattern_name` and are NEVER gated — so real keys, including the
        // `/`-bearing base64 ones (Slack webhooks, AWS secret keys with context), and
        // specific keys like GCP `AIza…`, still mask.
        if entity_type == "API_KEY"
            && r.recognition_metadata.pattern_name.as_deref() == Some(GENERIC_ENTROPY_PATTERN)
            && !plausible_generic_secret(slice)
        {
            continue;
        }
        if cfg.allow_list.is_allowed(slice) {
            allowed_spans.push((r.start, r.end));
            continue;
        }
        dets.push(CachedDetection {
            start: r.start,
            end: r.end,
            entity_type,
            score: r.score,
            source,
            literal: false,
            fixed_token: None,
        });
    }
}

/// Keep the best detection on overlap: custom > presidio/ml, then higher score,
/// then longer span. Returns the survivors sorted by `start`.
fn resolve_overlaps(mut dets: Vec<CachedDetection>) -> Vec<CachedDetection> {
    // Best first.
    dets.sort_by(|a, b| {
        let a_custom = a.source == Source::Custom;
        let b_custom = b.source == Source::Custom;
        b_custom
            .cmp(&a_custom)
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut kept: Vec<CachedDetection> = Vec::new();
    for d in dets {
        let overlaps = kept.iter().any(|k| d.start < k.end && k.start < d.end);
        if !overlaps {
            kept.push(d);
        }
    }
    kept.sort_by_key(|d| d.start);
    kept
}

// ---------------------------------------------------------------------------
// Generic high-entropy plausibility gate (defense-in-depth)
//
// A byte-for-byte mirror of presidio's own structural gate on its generic
// `Generic_High_Entropy_Token` catch-all, replicated here so zlauder rejects 32+-char
// file paths / identifiers / hex digests even when built against a presidio rev that
// predates the upstream fix. Kept intentionally identical to upstream so that, against
// a fixed presidio, this never drops a detection presidio would have kept (it only
// ever runs on the catch-all, which a fixed presidio already filters before we see it).
// ---------------------------------------------------------------------------

/// Returns true if `t` is a plausible opaque secret rather than a file path, code
/// identifier, hex digest, or UUID. See [`crate::detect`] module note above.
fn plausible_generic_secret(t: &str) -> bool {
    // Pure hex ⇒ digest / git SHA / content hash / id, never a generic key.
    if t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // Entropy floor: UUIDs (~3.4) and low-variety/repeating strings fall below a
    // genuine random secret (~4.5+).
    if shannon_entropy(t) < 4.0 {
        return false;
    }
    // Opaque tokens interleave letters AND digits.
    let has_alpha = t.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = t.bytes().any(|b| b.is_ascii_digit());
    if !(has_alpha && has_digit) {
        return false;
    }
    // Reads like natural-language / path text? High vowel density AND a long lowercase
    // run together mark prose-y segments (e.g. "…/projects/app42/mainmodulehandler").
    if vowel_ratio(t) >= 0.30 && max_lowercase_run(t) >= 6 {
        return false;
    }
    true
}

/// Byte-level Shannon entropy (bits/byte).
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Fraction of ASCII letters that are vowels (0.0 if no letters).
fn vowel_ratio(s: &str) -> f64 {
    let mut letters = 0u64;
    let mut vowels = 0u64;
    for b in s.bytes() {
        if b.is_ascii_alphabetic() {
            letters += 1;
            if matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u') {
                vowels += 1;
            }
        }
    }
    if letters == 0 {
        0.0
    } else {
        vowels as f64 / letters as f64
    }
}

/// Longest run of consecutive lowercase ASCII letters.
fn max_lowercase_run(s: &str) -> usize {
    let mut max = 0usize;
    let mut cur = 0usize;
    for b in s.bytes() {
        if b.is_ascii_lowercase() {
            cur += 1;
            max = max.max(cur);
        } else {
            cur = 0;
        }
    }
    max
}

#[cfg(test)]
mod context_enhancer_tests {
    use super::*;

    /// Build the analyzer the way `MaskEngine::from_parts` now does — with the
    /// context-aware enhancer wired in.
    fn enhanced_analyzer() -> presidio_analyzer::AnalyzerEngine {
        presidio_analyzer::default_analyzer("en")
            .with_context_enhancer(presidio_analyzer::LemmaContextAwareEnhancer::new())
    }

    fn phone_detected(text: &str) -> bool {
        let cfg = EngineConfig::default(); // Balanced: threshold 0.5, Contact on
        let dets = run_detection(
            &enhanced_analyzer(),
            &cfg,
            &[],
            None,
            text,
            Surface::UserMessage,
        )
        .unwrap();
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER")
    }

    #[test]
    fn phone_with_context_word_is_boosted_over_threshold() {
        // Base PHONE_NUMBER score is 0.4 (< 0.5 floor); the context word "Call"
        // within the prefix window lifts it to 0.75, so it now masks.
        assert!(
            phone_detected("Call me at +1 415 555 0132 about the contract."),
            "a phone with a nearby context word should clear the threshold"
        );
        assert!(
            phone_detected("My number is +1 415 555 0132."),
            "\"number\" is a phone context word and should boost the match"
        );
    }

    #[test]
    fn bare_phone_without_context_stays_below_threshold() {
        // No phone context word nearby: the 0.4 base stays below the 0.5 floor.
        // (Documents the tradeoff — context boosts recall; ML or an explicit
        // per-entity PHONE_NUMBER operator is the lever for context-free phones. Note
        // even Strict's 0.4 floor no longer masks a context-free phone: the
        // `PHONE_BASE_SCORE` tie-break in `ingest_results` drops the at-base run, so a
        // phone-shaped order/id number is not a false positive there either.)
        assert!(
            !phone_detected("The reference value is +1 415 555 0132 exactly."),
            "a context-free phone should remain below the default threshold"
        );
    }

    /// The Strict profile's floor (0.4) ties the phone base score (0.4), so the plain
    /// `<` floor would let a context-free phone-shaped run through. The targeted
    /// `PHONE_BASE_SCORE` tie-break must drop it (no context word ⇒ still at base), so a
    /// bare order/id number does NOT mask even under Strict — while a context-bearing
    /// phone (boosted to 0.75) still masks under Strict.
    #[test]
    fn strict_drops_context_free_phone_tie_but_keeps_boosted() {
        fn phone_detected_strict(text: &str) -> bool {
            let cfg = EngineConfig::for_profile(crate::Profile::Strict); // floor 0.4
            run_detection(
                &enhanced_analyzer(),
                &cfg,
                &[],
                None,
                text,
                Surface::UserMessage,
            )
            .unwrap()
            .iter()
            .any(|d| d.entity_type == "PHONE_NUMBER")
        }
        // Context-free phone-shaped number at exactly the 0.4 base: dropped even at the
        // Strict 0.4 floor (this is the "Order #4021558" false-positive shape).
        assert!(
            !phone_detected_strict("Order #4021558 shipped"),
            "a context-free phone-shaped run must not mask at Strict (was the Order# FP)"
        );
        assert!(
            !phone_detected_strict("The reference value is +1 415 555 0132 exactly."),
            "a context-free phone stays unmasked at Strict (needs a context word or ML)"
        );
        // A context word lifts the same phone to 0.75 (> 0.4 base), so it still masks.
        assert!(
            phone_detected_strict("Call me at +1 415 555 0132 about the contract."),
            "a context-bearing phone still masks under Strict"
        );
    }

    /// Pins our local `PHONE_BASE_SCORE` to the upstream recognizer's flat phone score.
    /// If a presidio bump changes the base, this fails loudly so the tie-break stays
    /// aligned (a stale value would either re-admit the FP or over-drop real phones).
    #[test]
    fn phone_base_score_matches_upstream() {
        // Pin the local constant to presidio's flat phone score. If a presidio bump
        // changes the base, this fails loudly so the tie-break stays aligned (a stale
        // value would either re-admit the order-number FP or over-drop real phones).
        assert_eq!(PHONE_BASE_SCORE, 0.4, "phone base score constant");
        // With the floor dropped below the base, the tie-break is the ONLY thing that can
        // suppress a context-free phone — confirm it does (no PHONE_NUMBER survives).
        let cfg = EngineConfig {
            score_threshold: 0.0,
            ..EngineConfig::default()
        };
        let dets = run_detection(
            &enhanced_analyzer(),
            &cfg,
            &[],
            None,
            "The reference value is +1 415 555 0132 exactly.",
            Surface::UserMessage,
        )
        .unwrap();
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "context-free phone dropped by the PHONE_BASE_SCORE tie-break even at floor 0"
        );
    }

    /// A real (non-placeholder) SSN is still detected and survives every profile floor
    /// — the phone tie-break is scoped to PHONE_NUMBER and does NOT touch US_SSN. (The
    /// SSN5 pattern scores 0.5, above Strict 0.4 and at/above the others, and a
    /// non-sample area number passes presidio's `invalidate_result`.) This pins that the
    /// phone-FP fix did not weaken SSN masking.
    #[test]
    fn real_ssn_still_masks_under_strict() {
        let cfg = EngineConfig::for_profile(crate::Profile::Strict); // floor 0.4
        let dets = run_detection(
            &enhanced_analyzer(),
            &cfg,
            &[],
            None,
            "ssn 536-90-4399 on file",
            Surface::UserMessage,
        )
        .unwrap();
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "a real SSN must still mask under Strict after the phone-FP fix, got {dets:?}"
        );
    }

    #[test]
    fn context_artifacts_are_byte_correct_across_multibyte() {
        // Token byte offsets must index the original string correctly even after a
        // multibyte char, so the enhancer's window lands on the right words.
        let text = "Café — call +1 415 555 0132";
        let a = context_artifacts(text, "en");
        for t in &a.tokens {
            assert_eq!(
                &text[t.start..t.end],
                t.text,
                "token offsets must be byte-correct"
            );
        }
        assert!(a.tokens.iter().any(|t| t.text == "Café"));
        assert_eq!(a.tokens.len(), a.lemmas.len(), "lemmas parallel tokens");
        assert!(a.lemmas.iter().any(|l| l == "call"));
    }
}

#[cfg(test)]
mod precision_tests {
    use super::*;

    // Paths, identifiers, hashed asset names, hex digests, and UUIDs are NOT secrets.
    #[test]
    fn generic_gate_rejects_paths_identifiers_and_digests() {
        for s in [
            "/home/user/Projects/zlauder-testbed/finance-notes",
            "/home/user2/projects/app42/src/mainmodulehandler",
            "VeryLongCamelCaseComponentNameThatExceedsThirtyTwoChars",
            "this-is-a-rather-long-kebab-case-filename-indeed",
            "this_is_a_very_long_snake_case_identifier_name_here",
            "4f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c", // 32-hex digest
            "0123456789abcdef0123456789abcdef", // uniform 32-hex (entropy 4.0)
            "550e8400-e29b-41d4-a716-446655440000", // UUID
        ] {
            assert!(
                !plausible_generic_secret(s),
                "should reject non-secret: {s:?}"
            );
        }
    }

    // Real opaque tokens — including ones that legitimately contain '/' — must pass.
    #[test]
    fn generic_gate_keeps_real_opaque_tokens() {
        for s in [
            "k7Lm2Nq9Rp4StUvWxYzAbCdEfGhIjKlMnOp",          // bare base62
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",     // AWS secret w/ slash
            "dGhpc2lzYVZlcnlMb25nU2VjcmV0VmFsdWUxMjM0NTY3", // base64 blob
        ] {
            assert!(plausible_generic_secret(s), "should keep secret: {s:?}");
        }
    }
}

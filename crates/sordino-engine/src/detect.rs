//! Detection: presidio analyzer + custom rules, filtered and overlap-resolved
//! into a sorted, non-overlapping span list with a resolved operator each.

use presidio_analyzer::recognizers::GENERIC_ENTROPY_PATTERN;
use presidio_analyzer::{AnalyzeRequest, AnalyzerEngine};
use presidio_core::{NlpArtifacts, RecognizerResult, Token};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;

use crate::cache::{CachedDetection, Source};
use crate::config::{CustomReplacement, EngineConfig, Operator};
use crate::error::EngineError;
use crate::ml_api::MlRecognizer;
use crate::secrets::{CompiledSecret, detect_secrets};
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
// v6: added the sordino-local hard-context recognizers — DATE_OF_BIRTH,
// CREDIT_CARD_EXPIRATION / EXPIRATION_DATE (confidence-tiered), and CVV — registered in
// `MaskEngine::from_parts`, plus the ML `private_date` → PRIVATE_DATE remap. New
// recognizers + the remap change detection output for unchanged text, so bump to abandon
// stale cache entries that predate them.
// v7: added the context-based UrlCredentialRecognizer → URL_CREDENTIAL (Secrets). It
// masks sensitive-named query-param values and URL userinfo regardless of value shape,
// so a credential inside a URL stays masked after URL/IP/MAC moved to the (default-off)
// `Network` category. New recognizer changes output for unchanged text — bump to abandon
// stale cache.
// v8: UrlCredentialRecognizer now skips non-Bearer auth schemes (Basic/Digest/Negotiate/
// NTLM), incl. after a JSON-quoted name, so `Authorization: Basic <b64>` masks the
// credential; and it scans EVERY percent-decode level (to a bounded fixpoint) so multiply-
// and mixed-encoded (`%253D`, `%2526`) structures are caught. These change detection output
// for unchanged text — bump.
// v9: UrlCredentialRecognizer's value-capture groups now require 2+ chars (was 1+), so a
// bare context word (`session`, `sig`, ...) next to a single character no longer masks as
// a credential. Also added the `preserve_current_date` near-now-date suppression pass
// (`is_near_now_date`/`is_suppressed`, wired into both the custom-rule pass and
// `ingest_results`) and extended `AllowList::with_common_words()`. All three change
// detection output for unchanged (text, config) — bump to abandon stale cache entries.
// v10: upstream presidio-analyzer now ships a dedicated whole-block PrivateKeyRecognizer
// (native EntityType::PrivateKey → "PRIVATE_KEY", in Category::Secrets/always-on),
// registered in its default recognizer set. A full `-----BEGIN … PRIVATE KEY-----`…
// `-----END-----` block now masks ENTIRELY (base64 body included) instead of only the
// marker line matching as API_KEY. Changes detection output for unchanged text — bump.
pub const DETECTOR_VERSION: u64 = 10;

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
    if let Some(op) = det.secret_op {
        // A registered secret carries its resolved operator (Hash/Redact/Mask/Broker),
        // keyed by `secrets_fp` in the cache key so it is safe to memoize.
        op
    } else if det.literal {
        Operator::Token
    } else {
        cfg.operator_for(&det.entity_type)
    }
}

pub fn run_detection(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    secrets: &[CompiledSecret],
    ml: Option<&dyn MlRecognizer>,
    text: &str,
    surface: Surface,
) -> Result<Vec<CachedDetection>, EngineError> {
    let (mut dets, mut allowed_spans, today) =
        detect_base(analyzer, cfg, customs, secrets, text, surface);

    // Pass 2b: the optional ML recognizer (openai/privacy-filter), if loaded. It
    // returns the same `RecognizerResult` type, so it flows through the identical
    // category gate / allow-list / overlap dedup below — e.g. its PERSON/LOCATION
    // spans only mask when the `personal` category is on. Tagged `Source::Ml` so the
    // deferred Component-3 burn can single it out.
    if let Some(rec) = ml {
        // `MlRecognizer` is fallible BY DESIGN: an empty result would FAIL OPEN —
        // the leaf would ride upstream with free-text PII unscanned. Both backends
        // are a `TokenClassifierRecognizer` whose impl drives the fail-CLOSED
        // `try_analyze` (a backend error — e.g. an unreachable http endpoint —
        // becomes `Err`) under a panic guard (catch_unwind, which `try_analyze`
        // does not cover). The `?` flows into the caller's fail-safe: refuse.
        let ml_results = rec.analyze(text)?;
        ingest_results(
            ml_results,
            cfg,
            text,
            &mut dets,
            &mut allowed_spans,
            Source::Ml,
            today,
        );
    }

    Ok(finish(dets, allowed_spans))
}

/// Batched sibling of [`run_detection`]: detect across MANY leaves with a SINGLE
/// ML forward. The expensive ML token-classification runs once over all texts via
/// [`MlRecognizer::analyze_batch`] (which the candle recognizer overrides to a padded
/// batched forward — span-equivalent to looping `analyze` within a tight score
/// tolerance); the cheap per-leaf regex/custom passes still run per leaf via the
/// shared [`detect_base`]. Result `[i]` is the detection list for `leaves[i]`,
/// IDENTICAL to `run_detection(.., Some(ml), leaves[i].0, leaves[i].1)` up to that
/// ML tolerance — this is the engine-side recall contract gated by the prewarm
/// parity test.
///
/// `analyze_batch` is all-or-nothing: any backend error aborts the whole batch.
/// The caller (`prewarm_batch`) treats an `Err` as "skip the prewarm" and lets the
/// per-leaf `mask` path re-run (and fail-safe) on its own, so a batched failure
/// never changes a request's outcome.
pub fn run_detection_batch(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    secrets: &[CompiledSecret],
    ml: &dyn MlRecognizer,
    leaves: &[(&str, Surface)],
) -> Result<Vec<Vec<CachedDetection>>, EngineError> {
    let texts: Vec<&str> = leaves.iter().map(|(t, _)| *t).collect();
    // Fallible by design — a batched endpoint failure aborts the whole batch
    // (the prewarm caller skips it and lets the per-leaf path re-run and
    // fail-safe on its own).
    let ml_batch = ml.analyze_batch(&texts)?;
    // The trait contract is one result vector per input, index-aligned. Guard it:
    // a wrong-length response would mis-route ML spans to the wrong leaf (a silent
    // cross-leaf leak), so refuse the batch instead and fall back to per-leaf.
    if ml_batch.len() != leaves.len() {
        return Err(EngineError::Ml(format!(
            "analyze_batch returned {} result(s) for {} input(s)",
            ml_batch.len(),
            leaves.len()
        )));
    }

    let mut out = Vec::with_capacity(leaves.len());
    for ((text, surface), ml_results) in leaves.iter().zip(ml_batch) {
        let (mut dets, mut allowed_spans, today) =
            detect_base(analyzer, cfg, customs, secrets, text, *surface);
        ingest_results(
            ml_results,
            cfg,
            text,
            &mut dets,
            &mut allowed_spans,
            Source::Ml,
            today,
        );
        out.push(finish(dets, allowed_spans));
    }
    Ok(out)
}

/// Pass 1 (custom rules) + Pass 2 (presidio regex analyzer) for one leaf, BEFORE
/// the ML pass and BEFORE allow-list suppression / overlap resolution. Returns the
/// partial detection list plus the allow-listed spans. Shared verbatim by per-leaf
/// [`run_detection`] and batched [`run_detection_batch`] so the non-ML detection is
/// byte-identical across both paths.
fn detect_base(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    secrets: &[CompiledSecret],
    text: &str,
    surface: Surface,
) -> (Vec<CachedDetection>, Vec<(usize, usize)>, i64) {
    let mut dets: Vec<CachedDetection> = Vec::new();
    // Spans of allow-listed values; any detection fully contained in one of these
    // is also suppressed (allow-listing "admin@example.com" covers its
    // "example.com" sub-domain too).
    let mut allowed_spans: Vec<(usize, usize)> = Vec::new();
    // Computed once per leaf and reused for every date-shaped candidate below (and
    // returned to the caller, which folds it into the cache key — see
    // `is_near_now_date`'s doc for why the cache MUST vary by day).
    let today = today_days();

    // Pass 0: registered secrets (exact-literal). Highest overlap priority and EXEMPT
    // from allow-list suppression (a registered secret is never silently passed
    // through, even if it also matches an allow-list entry).
    dets.extend(detect_secrets(secrets, text, surface));

    // Pass 1: custom rules (already priority-sorted).
    for c in customs {
        if let Some(surfs) = &c.surfaces
            && !surfs.contains(&surface)
        {
            continue;
        }
        for m in c.re.find_iter(text) {
            let slice = &text[m.start()..m.end()];
            if is_suppressed(cfg, slice, today) {
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
                secret_op: None,
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
        today,
    );

    (dets, allowed_spans, today)
}

/// Days since the Unix epoch, from the wall clock (UTC day boundary). Used both to
/// evaluate [`is_near_now_date`] and — returned by [`detect_base`] up to the cache
/// key — to bucket the detection cache by calendar day (see that type's doc: without
/// this, a "date is near now" verdict cached today would be served, unchanged, on
/// every future day, silently un-suppressing or over-suppressing a date once it's no
/// longer near "now"). Falls back to epoch day 0 on a clock error (pre-1970 clock;
/// never happens in practice) rather than panicking — worst case that request's
/// near-now check simply never matches.
pub(crate) fn today_days() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// Howard Hinnant's `days_from_civil`: proleptic-Gregorian (year, month, day) →
/// days since the Unix epoch. No date/time crate dependency for the one conversion
/// the engine needs. `month`/`day` are assumed already range-checked by the caller
/// ([`parse_calendar_date`]) — this function does not itself validate.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse a detected span as an unambiguous, year-first calendar date — `YYYY-MM-DD`
/// or `YYYY/MM/DD` only. Deliberately NOT day-first/month-first (`DD/MM/YYYY`,
/// `MM/DD/YYYY`): those are what the DOB recognizer captures, and are ambiguous to
/// parse without knowing the locale — misreading one as day-first when it's
/// month-first (or vice versa) could accidentally rate a real birthdate as
/// "near now". Returns days-since-epoch, or `None` if the slice isn't exactly this
/// 10-byte shape or the month/day are out of range.
fn parse_calendar_date(slice: &str) -> Option<i64> {
    let b = slice.as_bytes();
    if b.len() != 10 {
        return None;
    }
    let sep = b[4];
    if (sep != b'-' && sep != b'/') || b[7] != sep {
        return None;
    }
    let is_digit = |c: u8| c.is_ascii_digit();
    if !(b[0..4].iter().all(|&c| is_digit(c))
        && b[5..7].iter().all(|&c| is_digit(c))
        && b[8..10].iter().all(|&c| is_digit(c)))
    {
        return None;
    }
    let year: i64 = slice[0..4].parse().ok()?;
    let month: i64 = slice[5..7].parse().ok()?;
    let day: i64 = slice[8..10].parse().ok()?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// Number of days in `month` (1-12) of the proleptic-Gregorian `year`, leap years
/// included (divisible by 4, except centuries not divisible by 400). `parse_calendar_date`
/// calls this AFTER bounding `month` to 1..=12, so the exhaustive match never sees an
/// out-of-range month. Without this, an impossible date like `2026-02-30` or a
/// non-leap `2026-02-29` would still parse via `days_from_civil`'s unchecked civil-date
/// math (which normalizes it forward into March) and could be wrongly compared against
/// "today" — this closes that gap.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// How many days of slack around "today" still counts as "the current date" for
/// `preserve_current_date` (see that config field's doc). `1` covers today plus one
/// day either side — timezone skew between the proxy host's clock and whatever
/// clock the harness/model used when it said "today" — while still being far too
/// narrow to accidentally cover a real near-term date (an appointment next week, a
/// document dated last month) as a false negative on masking.
const NEAR_NOW_WINDOW_DAYS: i64 = 1;

/// Does `slice` parse as a calendar date within [`NEAR_NOW_WINDOW_DAYS`] of `today`?
/// Entity-type-agnostic by design (mirrors `AllowList::is_allowed`, which this sits
/// alongside): it doesn't matter WHY something detected this span as date-shaped —
/// DOB regex, the ML `private_date` label, a custom rule — if the exact text is a
/// calendar date near now, it's the harness's own current-date fact, not PII.
fn is_near_now_date(slice: &str, today: i64) -> bool {
    parse_calendar_date(slice).is_some_and(|d| (d - today).abs() <= NEAR_NOW_WINDOW_DAYS)
}

/// One suppression gate shared by the custom-rule pass and [`ingest_results`]: an
/// allow-listed value, or (`preserve_current_date`) a near-now calendar date.
fn is_suppressed(cfg: &EngineConfig, slice: &str, today: i64) -> bool {
    cfg.allow_list.is_allowed(slice) || (cfg.preserve_current_date && is_near_now_date(slice, today))
}

/// Suppress detections fully contained within an allow-listed span, then resolve
/// overlaps into the final sorted, non-overlapping list. Shared tail of
/// [`run_detection`] and [`run_detection_batch`].
fn finish(
    mut dets: Vec<CachedDetection>,
    allowed_spans: Vec<(usize, usize)>,
) -> Vec<CachedDetection> {
    // Suppress detections fully contained within an allow-listed span — EXCEPT
    // registered secrets (Pass-0), which are never silently passed through.
    if !allowed_spans.is_empty() {
        dets.retain(|d| {
            d.source == Source::Secret
                || !allowed_spans
                    .iter()
                    .any(|(s, e)| *s <= d.start && d.end <= *e)
        });
    }
    resolve_overlaps(dets)
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
    today: i64,
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
        // sordino masks a code-heavy traffic domain where 32+-char file paths, hashed
        // asset names, hex digests, and long identifiers are everywhere — exactly what
        // that catch-all cannot tell apart from an opaque key. We re-apply presidio's
        // own structural gate here so sordino stays correct even when built against a
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
        if is_suppressed(cfg, slice, today) {
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
            secret_op: None,
        });
    }
}

/// Keep the best detection on overlap: secret > custom > presidio/ml, then higher
/// score, then longer span. Returns the survivors sorted by `start`. `pub(crate)` so
/// the secrets-only fast paths (disabled-surface / user-bypass) resolve overlaps
/// among registered secrets too, never feeding `apply()` overlapping spans.
pub(crate) fn resolve_overlaps(mut dets: Vec<CachedDetection>) -> Vec<CachedDetection> {
    // Best first. Priority TIER (exhaustive `match` so a new `Source` variant
    // compile-forces a decision here): a registered secret outranks a custom rule,
    // which outranks regex/ML. Then higher score, then longer span.
    fn tier(s: Source) -> u8 {
        match s {
            Source::Secret => 0,
            Source::Custom => 1,
            Source::Regex | Source::Ml => 2,
        }
    }
    dets.sort_by(|a, b| {
        tier(a.source)
            .cmp(&tier(b.source))
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
// `Generic_High_Entropy_Token` catch-all, replicated here so sordino rejects 32+-char
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
mod current_date_tests {
    use super::*;
    use crate::config::CustomReplacement;

    fn analyzer() -> presidio_analyzer::AnalyzerEngine {
        presidio_analyzer::default_analyzer("en")
    }

    /// Inverse of `days_from_civil` (Howard Hinnant's `civil_from_days`), test-only:
    /// production code never needs to render a date, only parse one, but tests need
    /// to build date strings relative to the ACTUAL wall clock (not a fixed literal,
    /// which would silently stop testing "near now" the day it stops being near now).
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let y = if m <= 2 { y + 1 } else { y };
        (y, m as u32, d as u32)
    }

    fn date_offset_from_today(offset_days: i64) -> String {
        let (y, m, d) = civil_from_days(today_days() + offset_days);
        format!("{y:04}-{m:02}-{d:02}")
    }

    /// A synthetic date-matching recognizer standing in for a real date detector
    /// (DOB regex / ML `private_date`) — proves the suppression composes with ANY
    /// recognizer, exactly like `AllowList` does, without pulling in ML plumbing.
    fn date_custom() -> Vec<CompiledCustom> {
        compile_customs(&[CustomReplacement {
            pattern: r"\d{4}[-/]\d{2}[-/]\d{2}".to_string(),
            entity_type: "TEST_DATE".to_string(),
            is_regex: true,
            case_sensitive: true,
            priority: 0,
            literal_token: false,
            token: None,
            apply_to_surfaces: None,
        }])
        .expect("test custom rule must compile")
    }

    fn test_date_hits(cfg: &EngineConfig, text: &str) -> Vec<(usize, usize)> {
        let customs = date_custom();
        let (dets, allowed, _today) =
            detect_base(&analyzer(), cfg, &customs, &[], text, Surface::UserMessage);
        finish(dets, allowed)
            .into_iter()
            .filter(|d| d.entity_type == "TEST_DATE")
            .map(|d| (d.start, d.end))
            .collect()
    }

    #[test]
    fn parse_calendar_date_accepts_iso_and_slash_year_first_only() {
        assert_eq!(parse_calendar_date("2026-07-04"), Some(days_from_civil(2026, 7, 4)));
        assert_eq!(parse_calendar_date("2026/07/04"), Some(days_from_civil(2026, 7, 4)));
        // Day/month-first (DOB shape) is NOT parsed as a calendar date here — that
        // ambiguity is exactly what would risk misreading a real birthdate.
        assert_eq!(parse_calendar_date("04/07/2026"), None);
        assert_eq!(parse_calendar_date("27/03/1985"), None);
        assert_eq!(parse_calendar_date("not-a-date-x"), None);
        assert_eq!(parse_calendar_date("2026-13-01"), None, "month out of range");
        assert_eq!(parse_calendar_date("2026-01-99"), None, "day out of range");
        // Leap-year / days-in-month validity, not just a bare 1..=31 range check.
        assert_eq!(parse_calendar_date("2026-02-30"), None, "February never has 30 days");
        assert_eq!(parse_calendar_date("2026-02-29"), None, "2026 is not a leap year");
        assert_eq!(
            parse_calendar_date("2024-02-29"),
            Some(days_from_civil(2024, 2, 29)),
            "2024 IS a leap year (div by 4, not a century)"
        );
        assert_eq!(parse_calendar_date("1900-02-29"), None, "1900 is a century, not div by 400 -> not leap");
        assert_eq!(
            parse_calendar_date("2000-02-29"),
            Some(days_from_civil(2000, 2, 29)),
            "2000 IS a leap year (div by 400)"
        );
        assert_eq!(parse_calendar_date("2026-04-31"), None, "April never has 31 days");
    }

    #[test]
    fn is_near_now_date_windows_correctly() {
        let today = 20_000i64; // arbitrary fixed epoch-day for a pure unit test
        assert!(is_near_now_date(
            &format!("{:04}-{:02}-{:02}", civil_from_days(today).0, civil_from_days(today).1, civil_from_days(today).2),
            today
        ));
        let (y, m, d) = civil_from_days(today + 1);
        assert!(is_near_now_date(&format!("{y:04}-{m:02}-{d:02}"), today), "1 day out is in-window");
        let (y, m, d) = civil_from_days(today - 1);
        assert!(is_near_now_date(&format!("{y:04}-{m:02}-{d:02}"), today), "1 day back is in-window");
        let (y, m, d) = civil_from_days(today + 2);
        assert!(!is_near_now_date(&format!("{y:04}-{m:02}-{d:02}"), today), "2 days out is outside the window");
    }

    #[test]
    fn todays_date_anywhere_in_text_is_preserved() {
        let cfg = EngineConfig::default(); // preserve_current_date: true (the default)
        let today = date_offset_from_today(0);
        // No harness phrase at all — content-based, not a string match on "Today's
        // date is ...".
        let text = format!("Reminder: {today} is the current date.");
        assert!(test_date_hits(&cfg, &text).is_empty());
    }

    #[test]
    fn a_date_outside_the_window_still_masks() {
        let cfg = EngineConfig::default();
        let far_future = date_offset_from_today(30);
        let text = format!("The filing date on the document was {far_future}.");
        assert_eq!(test_date_hits(&cfg, &text).len(), 1);
    }

    #[test]
    fn near_now_date_survives_even_next_to_a_masked_far_date_in_the_same_text() {
        let cfg = EngineConfig::default();
        let today = date_offset_from_today(0);
        let far_future = date_offset_from_today(30);
        let text = format!("Today is {today}. The filing deadline is {far_future}.");
        let hits = test_date_hits(&cfg, &text);
        let far_start = text.find(&far_future).unwrap();
        assert_eq!(hits, vec![(far_start, far_start + far_future.len())], "{hits:?}");
    }

    #[test]
    fn preserve_current_date_false_masks_near_now_dates_too() {
        let cfg = EngineConfig {
            preserve_current_date: false,
            ..EngineConfig::default()
        };
        let today = date_offset_from_today(0);
        assert_eq!(
            test_date_hits(&cfg, &today).len(),
            1,
            "opt-out must let it mask like any other date"
        );
    }
}

#[cfg(test)]
mod precision_tests {
    use super::*;

    // Paths, identifiers, hashed asset names, hex digests, and UUIDs are NOT secrets.
    #[test]
    fn generic_gate_rejects_paths_identifiers_and_digests() {
        for s in [
            "/home/user/Projects/sordino-testbed/finance-notes",
            "/home/user2/projects/app42/src/mainmodulehandler",
            "VeryLongCamelCaseComponentNameThatExceedsThirtyTwoChars",
            "this-is-a-rather-long-kebab-case-filename-indeed",
            "this_is_a_very_long_snake_case_identifier_name_here",
            "4f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c", // 32-hex digest
            "0123456789abcdef0123456789abcdef", // uniform 32-hex (entropy 4.0)
            "da39a3ee5e6b4b0d3255bfef95601890afd80709", // 40-hex git SHA-1
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "src/recognizers/url_credential_value_only_spans", // long path component
            "build-artifact-cache-key-for-the-ci-pipeline-step", // long kebab id
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

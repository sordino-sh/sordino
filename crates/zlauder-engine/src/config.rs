//! Engine configuration: profiles, entity categories, operators, allow-list, and
//! custom rules. Ported (trimmed) from orchestr8-privacy `config.rs`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::surface::Surface;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Strict,
    #[default]
    Balanced,
    Minimal,
    /// Secrets-only profile. Renamed from the former `DevelopmentSafe`; the
    /// `development_safe` serde alias keeps OLD configs/control-plane clients
    /// loading after the rename.
    #[serde(rename = "secrets_only", alias = "development_safe")]
    SecretsOnly,
}

impl Profile {
    /// Every profile variant, in lineup order. Single source of truth for any
    /// caller that needs to enumerate the profiles (tests, validation).
    pub const ALL: [Profile; 4] = [
        Profile::Strict,
        Profile::Balanced,
        Profile::Minimal,
        Profile::SecretsOnly,
    ];

    pub fn default_threshold(self) -> f32 {
        match self {
            Profile::Strict => 0.4,
            Profile::Balanced => 0.5,
            Profile::SecretsOnly => 0.6,
            Profile::Minimal => 0.6,
        }
    }

    pub fn default_categories(self) -> HashSet<Category> {
        use Category::*;
        let v: &[Category] = match self {
            Profile::Strict => &[Secrets, Financial, Identity, Contact, Personal],
            Profile::Balanced => &[Secrets, Financial, Identity, Contact],
            Profile::Minimal => &[Secrets, Financial],
            Profile::SecretsOnly => &[Secrets],
        };
        v.iter().copied().collect()
    }

    pub fn default_operator(self) -> Operator {
        // Every profile now masks with a REVERSIBLE deterministic token (so the
        // operator can always reveal/audit). Strict was changed from the previous
        // irreversible `Redact` to `Token` (approved owner change).
        let _ = self;
        Operator::Token
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secrets,
    Financial,
    Identity,
    Contact,
    Personal,
}

impl Category {
    /// Every category, for callers that need to enumerate the whole set.
    pub const ALL: [Category; 5] = [
        Category::Secrets,
        Category::Financial,
        Category::Identity,
        Category::Contact,
        Category::Personal,
    ];

    /// The canonical, deduplicated set of every `EntityType` Display string the
    /// categories cover. This is the SAME source `entity_types` returns, so a
    /// config validator can reject an `entity_operators` key / `custom_replacement`
    /// `entity_type` that names an alias or typo (which would otherwise be a silent
    /// no-op against the category gate).
    pub fn canonical_entity_types() -> HashSet<&'static str> {
        Category::ALL
            .iter()
            .flat_map(|c| c.entity_types().iter().copied())
            .collect()
    }

    /// Entity-type strings (matching `presidio_core::EntityType`'s `Display`) that
    /// belong to this category.
    pub fn entity_types(self) -> &'static [&'static str] {
        match self {
            Category::Secrets => &[
                "API_KEY",
                "AWS_ACCESS_KEY",
                "AWS_SECRET_KEY",
                "AZURE_KEY",
                "GCP_API_KEY",
                "PRIVATE_KEY",
                "JWT",
            ],
            Category::Financial => &[
                "CREDIT_CARD",
                // These MUST be the canonical `EntityType` Display strings, NOT the
                // parse aliases — the category gate matches on `Display`, so an alias
                // here silently drops every detection of that entity. The aliases are
                // `IBAN` (→ `IBAN_CODE`), `CRYPTO_WALLET`/`CRYPTO_ADDRESS` (→ `CRYPTO`),
                // `US_ROUTING_NUMBER` (→ `ABA_ROUTING_NUMBER`), and `US_BANK_ACCOUNT`
                // (→ `US_BANK_NUMBER`). The IbanRecognizer / CryptoRecognizer are in
                // the default `en` set, so the alias bug was masking nothing for them.
                "IBAN_CODE",
                "CRYPTO",
                "US_BANK_NUMBER",
                "ABA_ROUTING_NUMBER",
            ],
            Category::Identity => &[
                "US_SSN",
                "US_ITIN",
                "NATIONAL_ID",
                "PASSPORT",
                "US_PASSPORT",
                "UK_PASSPORT",
                "DRIVER_LICENSE",
                "US_DRIVER_LICENSE",
                "UK_DRIVING_LICENCE",
                // Canonical Display is `MEDICAL_LICENSE` (`US_MEDICAL_LICENSE` is a
                // parse alias). The UsMedicalLicenseRecognizer IS in the default set,
                // so the alias was silently dropping every hit.
                "MEDICAL_LICENSE",
                "US_NPI",
                "US_MBI",
                "UK_NHS",
                "UK_NINO",
            ],
            // URL relies on presidio's strict `UrlRecognizer` (the default since
            // its strict-mode change), which drops scheme-less `file.ext`/`opts.la`
            // false positives while keeping real URLs (scheme / www. / path).
            // DOMAIN stays OFF: its recognizer is still aggressive on filenames;
            // re-enable per-deployment via `entity_operators` if wanted.
            Category::Contact => &[
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "IP_ADDRESS",
                "URL",
                "MAC_ADDRESS",
            ],
            Category::Personal => &["PERSON", "LOCATION", "ORGANIZATION"],
        }
    }
    // NOTE: `DATE_TIME` (the ML model's `private_date` label) is deliberately not in
    // any category — dates are noisy (the regex `DateTimeRecognizer` is off by
    // default for the same reason), so the ML recognizer's date spans are dropped by
    // the category gate. It stays opt-in per deployment via an explicit
    // `entity_operators` entry (which `entity_enabled` honors). Locked by
    // `date_time_unmapped_by_default_but_opt_in` in lib.rs.
}

/// Scope of the deterministic token salt (DEFERRED behavior; the flag is parsed
/// but inert — see Component 3 of `glittery-bubbling-locket.md`).
/// - `Project` (today): one persisted per-project salt → cross-conversation token
///   determinism (stable Anthropic prompt-cache prefix on resume).
/// - `Conversation`: a per-conversation salt, keyed by a similarity-based content
///   fingerprint, so tokens do not correlate across conversations. NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltScope {
    #[default]
    Project,
    Conversation,
}

/// How widely a *burned* (pre-mask-exposed) value is redacted (DEFERRED behavior;
/// parsed but inert). `Leaf` redacts only the pre-ML occurrence; `Value` redacts
/// every occurrence (fully severs the token↔plaintext bridge at the cost of model
/// coherence). NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureRedactionScope {
    #[default]
    Leaf,
    Value,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Operator {
    /// Reversible deterministic blake3 token (default).
    #[default]
    Token,
    /// Irreversible: replace with `[REDACTED]`.
    Redact,
    /// Irreversible: keep the last `from_end` chars, replace the rest with `char`.
    Mask { char: char, from_end: usize },
    /// Irreversible: `[ENTITY:hash]`.
    Hash,
    /// Detected but left verbatim (e.g. an allow-list-by-policy passthrough).
    Keep,
}

#[derive(Clone, Debug, Default)]
pub struct AllowList {
    pub exact: HashSet<String>,
    pub exact_ci: HashSet<String>,
    pub patterns: Vec<regex::Regex>,
}

impl AllowList {
    /// A small set of common safe words/hosts unlikely to be PII.
    pub fn with_common_words() -> Self {
        let mut al = Self::default();
        for w in ["Anthropic", "Claude", "127.0.0.1"] {
            al.add_exact(w);
        }
        al.add_exact_ci("localhost");
        al
    }

    pub fn is_allowed(&self, value: &str) -> bool {
        if self.exact.contains(value) {
            return true;
        }
        let lower = value.to_lowercase();
        if self.exact_ci.contains(&lower) {
            return true;
        }
        self.patterns.iter().any(|p| p.is_match(value))
    }

    pub fn add_exact(&mut self, v: impl Into<String>) {
        self.exact.insert(v.into());
    }

    pub fn add_exact_ci(&mut self, v: impl Into<String>) {
        self.exact_ci.insert(v.into().to_lowercase());
    }

    pub fn add_pattern(&mut self, p: regex::Regex) {
        self.patterns.push(p);
    }

    /// Build an allow-list from raw config strings (compiling pattern strings),
    /// seeded with the common-words defaults. Lets callers avoid a `regex` dep.
    pub fn from_specs(
        exact: Vec<String>,
        exact_ci: Vec<String>,
        patterns: Vec<String>,
    ) -> Result<Self, regex::Error> {
        let mut al = Self::with_common_words();
        for e in exact {
            al.add_exact(e);
        }
        for e in exact_ci {
            al.add_exact_ci(e);
        }
        for p in patterns {
            al.add_pattern(regex::Regex::new(&p)?);
        }
        Ok(al)
    }
}

/// Display-time decoration for *unmasked assistant text* (Arrow 2 only). When a
/// token is restored to plaintext on its way to the terminal, the plaintext is
/// wrapped with `prefix`/`suffix` so the operator can SEE, at a glance, exactly
/// which spans of the assistant's reply were un-masked. This is purely a local
/// rendering aid:
///
/// - It is applied ONLY to `Surface::AssistantText` (the model's prose), never to
///   tool inputs, tool results, citations, or compaction — wrapping those could
///   corrupt a value the model is writing into a file or passing to a tool.
/// - On the next turn the wrapped reply is re-sent as assistant history; the mask
///   path strips the marker literals *before* detection (see `MaskEngine::mask`),
///   so upstream receives the bare token — byte-identical to a no-marker
///   round-trip, with zero added noise and a stable prompt-cache prefix.
///
/// The default `prefix`/`suffix` are ANSI escapes (a colored background + reset).
/// ANSI is out-of-band — the model cannot accidentally emit or override it the way
/// it can with markdown (`**bold**`) — at the cost of only rendering if the
/// surrounding harness passes raw escapes through (Claude Code renders model text
/// as markdown, so this is best confirmed empirically). Any prefix/suffix pair
/// works; pick markers that do NOT occur in ordinary prose, since the strip removes
/// the exact literals from re-sent assistant history (the default escapes never
/// collide; printable markers like a backtick would over-strip code spans).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealMarker {
    /// Master switch for the decoration. Off by default (no behavior change).
    #[serde(default)]
    pub enabled: bool,
    /// Inserted immediately before each un-masked value.
    #[serde(default = "default_marker_prefix")]
    pub prefix: String,
    /// Inserted immediately after each un-masked value.
    #[serde(default = "default_marker_suffix")]
    pub suffix: String,
}

/// `ESC[97;44m` — bright-white foreground on a blue background.
fn default_marker_prefix() -> String {
    "\u{1b}[97;44m".to_string()
}
/// `ESC[0m` — reset all attributes.
fn default_marker_suffix() -> String {
    "\u{1b}[0m".to_string()
}

impl Default for RevealMarker {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: default_marker_prefix(),
            suffix: default_marker_suffix(),
        }
    }
}

impl RevealMarker {
    /// On (and has at least one non-empty delimiter to add/strip).
    pub fn is_active(&self) -> bool {
        self.enabled && (!self.prefix.is_empty() || !self.suffix.is_empty())
    }

    /// Wrap one un-masked value for display: `prefix || value || suffix`.
    pub fn wrap(&self, value: &str) -> String {
        let mut s = String::with_capacity(self.prefix.len() + value.len() + self.suffix.len());
        s.push_str(&self.prefix);
        s.push_str(value);
        s.push_str(&self.suffix);
        s
    }

    /// Could `text` contain either delimiter? Cheap guard so the common
    /// (marker-free) leaf skips the allocation in [`Self::strip`].
    pub fn contained_in(&self, text: &str) -> bool {
        (!self.prefix.is_empty() && text.contains(&self.prefix))
            || (!self.suffix.is_empty() && text.contains(&self.suffix))
    }

    /// Remove every exact `prefix`/`suffix` literal — used on the mask path to peel
    /// a prior turn's display decoration off re-sent assistant history *before*
    /// detection runs, so detection sees the original value (no marker char fused to
    /// the PII) and upstream gets the bare token.
    pub fn strip(&self, text: &str) -> String {
        let mut out = if self.prefix.is_empty() {
            text.to_string()
        } else {
            text.replace(&self.prefix, "")
        };
        if !self.suffix.is_empty() && self.suffix != self.prefix {
            out = out.replace(&self.suffix, "");
        }
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomReplacement {
    pub pattern: String,
    pub entity_type: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub literal_token: bool,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub apply_to_surfaces: Option<HashSet<Surface>>,
}

/// Optional ML recognizer config (`[engine.ml]`): the `openai/privacy-filter`
/// token classifier on a native-Rust Candle CPU backend. Plain serde — parsed
/// even by a regex-only (`--no-default-features`) build, which simply never loads
/// a model. Activation is hot: the proxy loads the model in the background when
/// `enabled` flips true (see `MlStatus`), so masking keeps running (regex-only)
/// while it loads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlConfig {
    /// Whether the ML recognizer should be active. Loading happens in the
    /// background; until the model is `Ready`, masking is regex-only.
    #[serde(default)]
    pub enabled: bool,
    /// HuggingFace repo id of a privacy-filter–compatible checkpoint.
    #[serde(default = "default_ml_model")]
    pub model: String,
    /// Optional pinned revision (branch/tag/commit); `None` ⇒ `main`.
    #[serde(default)]
    pub revision: Option<String>,
    /// Recognizer score floor; `None` ⇒ the spec default (0.5). Distinct from the
    /// engine-wide `score_threshold`, which is *also* applied to ML detections.
    #[serde(default)]
    pub min_score: Option<f32>,
    /// Try CUDA/Metal before CPU. Default `false` (CPU); the GPU backends are not
    /// compiled in by default, so this falls through to CPU regardless.
    #[serde(default)]
    pub prefer_gpu: bool,
}

fn default_ml_model() -> String {
    "openai/privacy-filter".to_string()
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_ml_model(),
            revision: None,
            min_score: None,
            prefer_gpu: false,
        }
    }
}

impl MlConfig {
    /// Do the *model-affecting* params match `other` (ignoring `enabled`)? The
    /// proxy's reconcile uses this to decide whether a config change requires
    /// rebuilding the recognizer vs. a no-op.
    pub fn same_model_params(&self, other: &Self) -> bool {
        self.model == other.model
            && self.revision == other.revision
            && self.min_score == other.min_score
            && self.prefer_gpu == other.prefer_gpu
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineConfig {
    /// Master switch. When `false` the engine is a transparent passthrough on the
    /// mask (request) path — no detection, no tokens. Unmasking (response path)
    /// still runs, so tokens already in the transcript keep decoding. Toggled live
    /// via the proxy's control endpoint or persisted per scope.
    pub enabled: bool,
    pub profile: Profile,
    pub score_threshold: f32,
    pub enabled_categories: HashSet<Category>,
    pub default_operator: Operator,
    #[serde(default)]
    pub entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    pub language: String,
    /// Deprecated compatibility field. Detection errors are always fail-closed;
    /// config values of `false` are ignored at policy-install time.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub disabled_surfaces: HashSet<Surface>,
    /// Not deserialized directly (`regex::Regex` is not `Deserialize`); the proxy
    /// config loader builds this from raw strings and assigns it.
    #[serde(skip)]
    pub allow_list: AllowList,
    #[serde(default)]
    pub custom_replacements: Vec<CustomReplacement>,
    /// Optional ML recognizer (`openai/privacy-filter`, CPU). Off by default.
    #[serde(default)]
    pub ml: MlConfig,

    /// Display-time decoration for un-masked assistant text (see [`RevealMarker`]).
    /// Off by default; a display/apply-time concern, so it is NOT part of
    /// `detection_fingerprint` (changing it does not invalidate the detection cache).
    #[serde(default)]
    pub reveal_marker: RevealMarker,

    // --- Detection cache (Component 1) ------------------------------------
    /// Max entries in the in-memory detection cache (LRU). `0` disables + clears
    /// it live. Default ~50k leaves; an empty detection list (the ~95% clean-leaf
    /// case) is a tiny value, so this bounds memory well below it in practice.
    #[serde(default = "default_cache_cap")]
    pub detection_cache_cap: usize,

    // --- Deferred Component-3 / persistence scaffolding (INERT) ------------
    // The fields below are parsed and documented but currently NON-FUNCTIONAL.
    // They reserve the config surface so enabling the behavior later is not a
    // breaking schema change. See `glittery-bubbling-locket.md` Component 3.
    /// (INERT) Persist the detection cache to disk across proxy restarts.
    #[serde(default)]
    pub detection_cache_persist: bool,
    /// (INERT) Path for the persisted detection cache (`None` ⇒ a default under the
    /// proxy state dir, when persistence is built).
    #[serde(default)]
    pub detection_cache_path: Option<String>,
    /// (INERT) On the ML `Ready` transition, redact ("burn") values exposed in
    /// plaintext during the pre-ML window instead of re-tokenizing them.
    #[serde(default)]
    pub redact_exposed_on_ml: bool,
    /// (INERT) Leaf- vs value-scoped burn (see [`ExposureRedactionScope`]).
    #[serde(default)]
    pub exposure_redaction_scope: ExposureRedactionScope,
    /// (INERT) Salt scope (see [`SaltScope`]).
    #[serde(default)]
    pub salt_scope: SaltScope,
    /// (INERT) Drop `thinking` blocks following a retroactive redaction (the model
    /// saw the value un-redacted while producing that opaque thinking).
    #[serde(default)]
    pub drop_contaminated_thinking: bool,
}

/// Shadow of [`EngineConfig`] used ONLY for deserialization, so we can tell an
/// *absent* `score_threshold`/`enabled_categories`/`default_operator` apart from
/// one explicitly set to a default-looking value. This is what makes a load-bearing
/// `profile = "strict"` actually seed that profile's threshold/categories/operator:
/// a field left out of the config is `None` here and gets filled from
/// [`Profile::for_profile`]; an explicit field stays `Some` and OVERRIDES the seed.
///
/// `profile` itself keeps its serde default (Balanced) — the seed is a no-op when
/// no profile is set, because Balanced's defaults equal the historical serde
/// defaults, so a config with no `profile` is byte-for-byte unchanged.
// NOTE: deliberately NOT `deny_unknown_fields` — `WireConfig` deserializes via
// `#[serde(flatten)] engine: EngineConfig` alongside a sibling `allow_list` key,
// and flatten + deny_unknown_fields is unsupported by serde (the flattened struct
// would reject the sibling). Unknown keys are tolerated, matching prior behavior.
#[derive(Deserialize)]
struct EngineConfigShadow {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    profile: Profile,
    // The three profile-derived fields: absent ⇒ `None` ⇒ seed from `profile`.
    #[serde(default)]
    score_threshold: Option<f32>,
    #[serde(default)]
    enabled_categories: Option<HashSet<Category>>,
    #[serde(default)]
    default_operator: Option<Operator>,
    #[serde(default)]
    entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    language: String,
    #[serde(default = "default_true")]
    fail_closed: bool,
    #[serde(default)]
    disabled_surfaces: HashSet<Surface>,
    #[serde(default)]
    custom_replacements: Vec<CustomReplacement>,
    #[serde(default)]
    ml: MlConfig,
    #[serde(default)]
    reveal_marker: RevealMarker,
    #[serde(default = "default_cache_cap")]
    detection_cache_cap: usize,
    #[serde(default)]
    detection_cache_persist: bool,
    #[serde(default)]
    detection_cache_path: Option<String>,
    #[serde(default)]
    redact_exposed_on_ml: bool,
    #[serde(default)]
    exposure_redaction_scope: ExposureRedactionScope,
    #[serde(default)]
    salt_scope: SaltScope,
    #[serde(default)]
    drop_contaminated_thinking: bool,
}

impl<'de> Deserialize<'de> for EngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = EngineConfigShadow::deserialize(deserializer)?;
        // Seed any absent profile-derived field from the profile; an explicit value
        // (Some) overrides. With the default (Balanced) profile and all three fields
        // absent, this reproduces the historical serde defaults exactly.
        let score_threshold = s
            .score_threshold
            .unwrap_or_else(|| s.profile.default_threshold());
        let enabled_categories = s
            .enabled_categories
            .unwrap_or_else(|| s.profile.default_categories());
        let default_operator = s
            .default_operator
            .unwrap_or_else(|| s.profile.default_operator());
        Ok(EngineConfig {
            enabled: s.enabled,
            profile: s.profile,
            score_threshold,
            enabled_categories,
            default_operator,
            entity_operators: s.entity_operators,
            language: s.language,
            fail_closed: s.fail_closed,
            disabled_surfaces: s.disabled_surfaces,
            allow_list: AllowList::with_common_words(),
            custom_replacements: s.custom_replacements,
            ml: s.ml,
            reveal_marker: s.reveal_marker,
            detection_cache_cap: s.detection_cache_cap,
            detection_cache_persist: s.detection_cache_persist,
            detection_cache_path: s.detection_cache_path,
            redact_exposed_on_ml: s.redact_exposed_on_ml,
            exposure_redaction_scope: s.exposure_redaction_scope,
            salt_scope: s.salt_scope,
            drop_contaminated_thinking: s.drop_contaminated_thinking,
        })
    }
}

fn default_true() -> bool {
    true
}
fn default_language() -> String {
    "en".to_string()
}
fn default_cache_cap() -> usize {
    50_000
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: Profile::Balanced,
            score_threshold: 0.5,
            enabled_categories: Profile::Balanced.default_categories(),
            default_operator: Operator::Token,
            entity_operators: HashMap::new(),
            language: "en".to_string(),
            fail_closed: true,
            disabled_surfaces: HashSet::new(),
            allow_list: AllowList::with_common_words(),
            custom_replacements: Vec::new(),
            ml: MlConfig::default(),
            reveal_marker: RevealMarker::default(),
            detection_cache_cap: default_cache_cap(),
            detection_cache_persist: false,
            detection_cache_path: None,
            redact_exposed_on_ml: false,
            exposure_redaction_scope: ExposureRedactionScope::default(),
            salt_scope: SaltScope::default(),
            drop_contaminated_thinking: false,
        }
    }
}

impl EngineConfig {
    /// A config seeded from a profile's threshold/categories/operator.
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            profile,
            score_threshold: profile.default_threshold(),
            enabled_categories: profile.default_categories(),
            default_operator: profile.default_operator(),
            ..Self::default()
        }
    }

    /// Validate `entity_operators` keys against the FULL `presidio_core::EntityType`
    /// canonical Display set — NOT category membership. Returns the list of unknown
    /// / alias / typo'd keys so a caller can reject or warn.
    ///
    /// Why the full Display set, not [`Category::canonical_entity_types`]: a key is a
    /// valid, functional `entity_operators` lever as long as it names a real canonical
    /// `EntityType` Display string, even if that type is deliberately in NO category.
    /// Two such types are documented opt-in levers driven exactly through this map:
    /// `DATE_TIME` (re-enabled per deployment via an explicit `entity_operators` entry
    /// — proven by `date_time_unmapped_by_default_but_opt_in` in lib.rs) and `DOMAIN`
    /// (re-enable per deployment if wanted). Validating against category membership
    /// wrongly flagged both as unknown, 400-ing valid configs.
    ///
    /// Detection of typos vs aliases: resolve each key with
    /// [`presidio_core::EntityType::from_str`] (infallible — an unknown label becomes
    /// `Custom`):
    ///   - `Custom(_)`            ⇒ no canonical match at all ⇒ typo (e.g. "EMIAL"), flag.
    ///   - `canonical_name() != key` ⇒ a known label but an ALIAS spelling (e.g.
    ///     "IBAN" → "IBAN_CODE"); the lookup tables match on the canonical Display, so
    ///     the alias key is a silent no-op ⇒ flag.
    ///   - `canonical_name() == key` ⇒ a real canonical Display name (incl.
    ///     DATE_TIME / DOMAIN) ⇒ accept.
    ///
    /// WHY only `entity_operators` keys: an `entity_operators` key is a SILENT NO-OP
    /// if it is not a canonical Display name — `entity_enabled`/`operator_for` look it
    /// up by exact Display, so a typo or alias never matches a real detection and masks
    /// nothing. By contrast a `custom_replacement.entity_type` is NEVER a no-op: a
    /// custom rule is its own detector (it emits detections directly, bypassing the
    /// category gate — see `detect::run`), so it legitimately invents a fresh type
    /// name. A key that names one of those custom types is therefore ALSO valid (you
    /// can set an operator for your own custom type), so we treat a key as known if it
    /// is a canonical Display name OR names a declared `custom_replacement.entity_type`.
    pub fn unknown_entity_types(&self) -> Vec<String> {
        use std::str::FromStr;
        let custom: HashSet<&str> = self
            .custom_replacements
            .iter()
            .map(|c| c.entity_type.as_str())
            .collect();
        self.entity_operators
            .keys()
            .filter(|k| {
                if custom.contains(k.as_str()) {
                    return false;
                }
                // Infallible: unknown labels become `Custom` verbatim.
                let et = presidio_core::EntityType::from_str(k).expect("from_str is infallible");
                match et {
                    // No canonical match at all ⇒ typo (e.g. "EMIAL"). (Its
                    // `canonical_name()` echoes the label, so we MUST match the
                    // variant rather than compare strings.) Flag.
                    presidio_core::EntityType::Custom(_) => true,
                    // A known label: accept only the exact canonical Display spelling;
                    // an ALIAS spelling (e.g. "IBAN" → "IBAN_CODE") differs ⇒ flag.
                    other => other.canonical_name() != k.as_str(),
                }
            })
            .cloned()
            .collect()
    }

    /// Is `entity_type` subject to masking — either in an enabled category or with
    /// an explicit per-type operator override?
    pub fn entity_enabled(&self, entity_type: &str) -> bool {
        if self.entity_operators.contains_key(entity_type) {
            return true;
        }
        self.enabled_categories
            .iter()
            .any(|c| c.entity_types().contains(&entity_type))
    }

    /// Resolve the operator for an entity type (per-type override else default).
    pub fn operator_for(&self, entity_type: &str) -> Operator {
        self.entity_operators
            .get(entity_type)
            .copied()
            .unwrap_or(self.default_operator)
    }

    pub fn surface_enabled(&self, surface: Surface) -> bool {
        !self.disabled_surfaces.contains(&surface)
    }

    /// Fingerprint of every DETECTION-affecting input (folded into the cache key;
    /// audit #3/#6). A change here yields a fresh key space, so stale entries become
    /// unreachable with nothing to hand-invalidate.
    ///
    /// INCLUDES: the detector-version constant (audit #1 — bundled regex/custom
    /// recognizer code identity), score_threshold, language, enabled_categories, the
    /// entity_operators KEY SET (key *presence* gates detection via `entity_enabled`),
    /// custom_replacements (the patterns ARE the detection), and the allow_list.
    ///
    /// EXCLUDES (so these apply WITHOUT a cache miss): operator VALUES and
    /// `default_operator` (resolved at apply time), the `enabled` master switch and
    /// `disabled_surfaces` (their effect is the un-cached early-return passthrough),
    /// `fail_closed` (deprecated/no-op error policy), `profile` (only a seed for the
    /// derived fields), `ml` (covered by the separate `ml_fp`), `reveal_marker`
    /// (a display/apply-time decoration; the marker strip happens before this
    /// fingerprint is consulted, so the cache key already reflects its effect), and
    /// the cache / Component-3 scaffolding fields.
    ///
    /// All maps/sets are serialized in a canonical (sorted) order so semantically
    /// identical configs hash identically (audit #6). `custom_replacements` is hashed
    /// in Vec order because order can decide same-priority overlap ties.
    pub fn detection_fingerprint(&self) -> u64 {
        let mut h = blake3::Hasher::new();
        h.update(b"zlauder-policy-fp-v1");
        h.update(&crate::detect::DETECTOR_VERSION.to_le_bytes());
        h.update(&self.score_threshold.to_bits().to_le_bytes());
        h.update(self.language.as_bytes());
        h.update(&[0xff]);

        // enabled_categories — sorted by discriminant for canonical order.
        let mut cats: Vec<u8> = self.enabled_categories.iter().map(|c| *c as u8).collect();
        cats.sort_unstable();
        h.update(&cats);
        h.update(&[0xff]);

        // entity_operators KEYS only (values are apply-time) — sorted.
        let mut keys: Vec<&str> = self.entity_operators.keys().map(String::as_str).collect();
        keys.sort_unstable();
        for k in keys {
            h.update(k.as_bytes());
            h.update(&[0]);
        }
        h.update(&[0xff]);

        // custom_replacements — Vec order preserved (same-priority order matters).
        for c in &self.custom_replacements {
            fp_custom(&mut h, c);
        }
        h.update(&[0xff]);

        fp_allow_list(&mut h, &self.allow_list);

        let digest = h.finalize();
        u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("32-byte digest"))
    }
}

/// Canonical fingerprint contribution of one custom replacement rule.
fn fp_custom(h: &mut blake3::Hasher, c: &CustomReplacement) {
    h.update(c.pattern.as_bytes());
    h.update(&[0]);
    h.update(c.entity_type.as_bytes());
    h.update(&[0]);
    h.update(&[
        c.is_regex as u8,
        c.case_sensitive as u8,
        c.literal_token as u8,
    ]);
    h.update(&c.priority.to_le_bytes());
    match &c.token {
        Some(t) => {
            h.update(&[1]);
            h.update(t.as_bytes());
        }
        None => {
            h.update(&[0]);
        }
    };
    h.update(&[0]);
    match &c.apply_to_surfaces {
        None => {
            h.update(&[0]);
        }
        Some(set) => {
            h.update(&[1]);
            let mut surfs: Vec<u8> = set.iter().map(|s| *s as u8).collect();
            surfs.sort_unstable();
            h.update(&surfs);
        }
    };
    h.update(&[0xfe]);
}

/// Canonical fingerprint contribution of the allow-list (sets sorted; patterns by
/// source string, in declared order).
fn fp_allow_list(h: &mut blake3::Hasher, al: &AllowList) {
    let mut exact: Vec<&str> = al.exact.iter().map(String::as_str).collect();
    exact.sort_unstable();
    for e in exact {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    let mut ci: Vec<&str> = al.exact_ci.iter().map(String::as_str).collect();
    ci.sort_unstable();
    for e in ci {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    for p in &al.patterns {
        h.update(p.as_str().as_bytes());
        h.update(&[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_toml(s: &str) -> EngineConfig {
        toml::from_str(s).expect("config should parse")
    }

    fn from_json(s: &str) -> EngineConfig {
        serde_json::from_str(s).expect("config should parse")
    }

    // --- profile lineup -----------------------------------------------------

    #[test]
    fn profile_lineup_values() {
        assert_eq!(Profile::Strict.default_threshold(), 0.4);
        assert_eq!(Profile::Balanced.default_threshold(), 0.5);
        assert_eq!(Profile::Minimal.default_threshold(), 0.6);
        assert_eq!(Profile::SecretsOnly.default_threshold(), 0.6);
        // Strict masks reversibly (Token), NOT an irreversible Redact.
        assert_eq!(Profile::Strict.default_operator(), Operator::Token);
        assert_eq!(
            Profile::SecretsOnly.default_categories(),
            [Category::Secrets].into_iter().collect()
        );
    }

    #[test]
    fn secrets_only_serializes_to_snake_case() {
        let v = serde_json::to_value(Profile::SecretsOnly).unwrap();
        assert_eq!(v, serde_json::json!("secrets_only"));
    }

    #[test]
    fn development_safe_alias_still_parses() {
        // Back-compat: an OLD config naming the renamed profile keeps loading and
        // resolves to SecretsOnly (with that profile's seeded fields).
        let cfg = from_toml("profile = \"development_safe\"\n");
        assert_eq!(cfg.profile, Profile::SecretsOnly);
        assert_eq!(cfg.score_threshold, 0.6);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets].into_iter().collect()
        );
        // The new spelling parses too.
        assert_eq!(
            from_toml("profile = \"secrets_only\"\n").profile,
            Profile::SecretsOnly
        );
    }

    // --- load-bearing profile= seeding (item 2b) ----------------------------

    #[test]
    fn profile_only_seeds_threshold_categories_operator() {
        // A config that sets ONLY `profile` must take that profile's threshold,
        // categories, and operator — NOT the serde/Balanced defaults.
        let cfg = from_toml("profile = \"strict\"\n");
        assert_eq!(cfg.profile, Profile::Strict);
        assert_eq!(cfg.score_threshold, 0.4, "strict threshold seeded");
        assert_eq!(
            cfg.enabled_categories,
            Profile::Strict.default_categories(),
            "strict categories seeded (incl. Personal)"
        );
        assert!(cfg.enabled_categories.contains(&Category::Personal));
        assert_eq!(cfg.default_operator, Operator::Token);
    }

    #[test]
    fn profile_only_minimal_seeds() {
        let cfg = from_json(r#"{"profile":"minimal"}"#);
        assert_eq!(cfg.score_threshold, 0.6);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets, Category::Financial]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn explicit_field_overrides_profile_seed() {
        // An explicit threshold beats the profile's seed; categories still seed.
        let cfg = from_toml("profile = \"strict\"\nscore_threshold = 0.9\n");
        assert_eq!(cfg.profile, Profile::Strict);
        assert_eq!(cfg.score_threshold, 0.9, "explicit threshold wins");
        assert_eq!(
            cfg.enabled_categories,
            Profile::Strict.default_categories(),
            "categories still seeded from profile"
        );

        // Explicit categories beat the seed; threshold still seeds.
        let cfg = from_toml("profile = \"strict\"\nenabled_categories = [\"secrets\"]\n");
        assert_eq!(cfg.score_threshold, 0.4, "threshold still seeded");
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets].into_iter().collect(),
            "explicit categories win"
        );

        // Explicit operator beats the seed.
        let cfg = from_toml("profile = \"balanced\"\ndefault_operator = { kind = \"redact\" }\n");
        assert_eq!(cfg.default_operator, Operator::Redact);
    }

    #[test]
    fn no_profile_yields_historical_defaults() {
        // With NO profile and NO explicit fields, the config is byte-for-byte the
        // historical default (Balanced 0.5, Balanced categories, Token) — the seed
        // is a no-op because the default profile (Balanced) equals those defaults.
        let cfg = from_toml("");
        let def = EngineConfig::default();
        assert_eq!(cfg.profile, Profile::Balanced);
        assert_eq!(cfg.score_threshold, def.score_threshold);
        assert_eq!(cfg.enabled_categories, def.enabled_categories);
        assert_eq!(cfg.default_operator, def.default_operator);
        assert_eq!(cfg.score_threshold, 0.5);
    }

    #[test]
    fn explicit_fields_without_profile_are_honored() {
        // No profile, but explicit fields → exactly those values (default profile).
        let cfg = from_toml("score_threshold = 0.2\nenabled_categories = [\"contact\"]\n");
        assert_eq!(cfg.profile, Profile::Balanced);
        assert_eq!(cfg.score_threshold, 0.2);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Contact].into_iter().collect()
        );
    }

    #[test]
    fn each_layer_independently_seeds_or_overrides() {
        // Exhaustive small matrix over the four (profile?, threshold?) combos.
        // (none,none) → balanced 0.5
        assert_eq!(from_toml("").score_threshold, 0.5);
        // (profile,none) → seed
        assert_eq!(from_toml("profile=\"minimal\"").score_threshold, 0.6);
        // (none,threshold) → explicit, balanced profile
        assert_eq!(from_toml("score_threshold=0.33").score_threshold, 0.33);
        // (profile,threshold) → explicit wins
        assert_eq!(
            from_toml("profile=\"minimal\"\nscore_threshold=0.11").score_threshold,
            0.11
        );
    }

    // --- entity-type validation (item 2c) -----------------------------------

    #[test]
    fn unknown_entity_types_flags_typos_and_aliases() {
        let mut cfg = EngineConfig::default();
        // Canonical key → fine.
        cfg.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        // Alias (IBAN is the parse alias for IBAN_CODE) → flagged.
        cfg.entity_operators.insert("IBAN".into(), Operator::Redact);
        // Typo → flagged.
        cfg.entity_operators
            .insert("EMIAL".into(), Operator::Redact);
        let unknown = cfg.unknown_entity_types();
        assert!(unknown.contains(&"IBAN".to_string()));
        assert!(unknown.contains(&"EMIAL".to_string()));
        assert!(!unknown.contains(&"EMAIL_ADDRESS".to_string()));
    }

    #[test]
    fn entity_operators_opt_in_levers_not_flagged() {
        // DATE_TIME and DOMAIN are real canonical `EntityType` Display names that are
        // DELIBERATELY in NO category — they are the documented opt-in levers driven
        // through `entity_operators`. They must NOT be flagged as unknown even though
        // they appear in no `Category::entity_types()` list. (Validating against
        // category membership instead of the full Display set was the bug.)
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert("DATE_TIME".into(), Operator::Redact);
        cfg.entity_operators
            .insert("DOMAIN".into(), Operator::Redact);
        assert!(
            cfg.unknown_entity_types().is_empty(),
            "DATE_TIME/DOMAIN are valid opt-in entity_operators keys"
        );

        // Aliases and typos still get flagged alongside them.
        cfg.entity_operators.insert("IBAN".into(), Operator::Redact); // alias of IBAN_CODE
        cfg.entity_operators
            .insert("EMIAL".into(), Operator::Redact); // typo
        let unknown = cfg.unknown_entity_types();
        assert!(unknown.contains(&"IBAN".to_string()));
        assert!(unknown.contains(&"EMIAL".to_string()));
        assert!(!unknown.contains(&"DATE_TIME".to_string()));
        assert!(!unknown.contains(&"DOMAIN".to_string()));
    }

    #[test]
    fn custom_replacement_type_is_never_flagged() {
        let mut cfg = EngineConfig::default();
        cfg.custom_replacements.push(CustomReplacement {
            pattern: "ACME-1".into(),
            entity_type: "PROJECT_CODE".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: false,
            token: None,
            apply_to_surfaces: None,
        });
        // A custom rule is its own detector (bypasses the category gate), so its
        // invented entity_type is NEVER a no-op and is not flagged — even with no
        // matching entity_operators entry. This is the `CUSTOM_KEYWORD` UI-mask case.
        assert!(cfg.unknown_entity_types().is_empty());

        // An entity_operators key that NAMES that custom type is also known (you can
        // set the operator for your own custom type).
        cfg.entity_operators
            .insert("PROJECT_CODE".into(), Operator::Token);
        assert!(cfg.unknown_entity_types().is_empty());

        // But an operator key that is neither canonical NOR a custom type → flagged.
        cfg.entity_operators.insert("TYPO".into(), Operator::Token);
        assert_eq!(cfg.unknown_entity_types(), vec!["TYPO".to_string()]);
    }

    #[test]
    fn canonical_entity_types_covers_all_categories() {
        let canon = Category::canonical_entity_types();
        for c in Category::ALL {
            for et in c.entity_types() {
                assert!(canon.contains(et), "{et} missing from canonical set");
            }
        }
    }
}

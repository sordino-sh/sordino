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
    DevelopmentSafe,
}

impl Profile {
    pub fn default_threshold(self) -> f32 {
        match self {
            Profile::Strict => 0.3,
            Profile::Balanced => 0.5,
            Profile::DevelopmentSafe => 0.6,
            Profile::Minimal => 0.8,
        }
    }

    pub fn default_categories(self) -> HashSet<Category> {
        use Category::*;
        let v: &[Category] = match self {
            Profile::Strict => &[Secrets, Financial, Identity, Contact, Personal],
            Profile::Balanced => &[Secrets, Financial, Identity, Contact],
            Profile::Minimal => &[Secrets, Financial],
            Profile::DevelopmentSafe => &[Secrets],
        };
        v.iter().copied().collect()
    }

    pub fn default_operator(self) -> Operator {
        match self {
            Profile::Strict => Operator::Redact,
            _ => Operator::Token,
        }
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
                "IBAN",
                "CRYPTO_WALLET",
                "CRYPTO_ADDRESS",
                "US_BANK_ACCOUNT",
                "US_ROUTING_NUMBER",
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
                "US_MEDICAL_LICENSE",
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
            Category::Contact => &["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "URL", "MAC_ADDRESS"],
            Category::Personal => &["PERSON", "LOCATION", "ORGANIZATION"],
        }
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default)]
    pub profile: Profile,
    #[serde(default = "default_threshold")]
    pub score_threshold: f32,
    #[serde(default = "default_categories")]
    pub enabled_categories: HashSet<Category>,
    #[serde(default)]
    pub default_operator: Operator,
    #[serde(default)]
    pub entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default)]
    pub disabled_surfaces: HashSet<Surface>,
    /// Not deserialized directly (`regex::Regex` is not `Deserialize`); the proxy
    /// config loader builds this from raw strings and assigns it.
    #[serde(skip)]
    pub allow_list: AllowList,
    #[serde(default)]
    pub custom_replacements: Vec<CustomReplacement>,
}

fn default_true() -> bool {
    true
}
fn default_threshold() -> f32 {
    0.5
}
fn default_language() -> String {
    "en".to_string()
}
fn default_categories() -> HashSet<Category> {
    Profile::Balanced.default_categories()
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            profile: Profile::Balanced,
            score_threshold: 0.5,
            enabled_categories: Profile::Balanced.default_categories(),
            default_operator: Operator::Token,
            entity_operators: HashMap::new(),
            language: "en".to_string(),
            fail_closed: false,
            disabled_surfaces: HashSet::new(),
            allow_list: AllowList::with_common_words(),
            custom_replacements: Vec::new(),
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
}

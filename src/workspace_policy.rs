//! Administrator-selected namespace authority; never inferred from a request.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeMode {
    #[default]
    Fixed,
    VaultOwner,
}
impl ScopeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::VaultOwner => "vault-owner",
        }
    }
}

/// Raw labels only. Generated redaction keys are reserved: historical literal
/// uses require an offline staged-data compatibility review, never rekeying here.
pub fn validate_workspace(label: &str) -> Result<(), &'static str> {
    if label
        .strip_prefix("redacted-")
        .is_some_and(|suffix| suffix.len() == 64 && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("reserved_workspace");
    }
    if label.is_empty()
        || label.trim() != label
        || matches!(label, "." | "..")
        || label
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '/' | '\\'))
        || (label.as_bytes().get(1) == Some(&b':') && label.as_bytes()[0].is_ascii_alphabetic())
    {
        return Err("invalid_request");
    }
    if label.len() > 512 || label.chars().count() > 128 {
        return Err("resource_limit");
    }
    Ok(())
}

/// Request assertion only: the service compares this to protected startup state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub scope_mode: ScopeMode,
    pub legacy_root_key: String,
}

pub fn valid_root_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

//! Casefile model (charter §21).
//!
//! Every historically important residual between upb-rs and the pinned oracle
//! is shrunk into a permanent casefile:
//!
//! ```text
//! casefiles/<id>/
//!     README.md
//!     metadata.json
//!     input.bin / input.json
//!     oracle.json
//!     rust.json
//!     residual.json
//!     reproduce.sh
//! ```
//!
//! When a residual is fixed the casefile is NOT deleted; it is promoted into
//! the permanent regression corpus.

use serde::{Deserialize, Serialize};

/// Residual classification taxonomy (charter §2, "Classify every material
/// residual as one of ...").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualClass {
    /// Genuine Rust implementation defect.
    RustDefect,
    /// The oracle model is incomplete; the court does not capture the real
    /// upstream behavior.
    IncompleteOracleModel,
    /// Platform difference (OS, architecture, libc, ...).
    PlatformDifference,
    /// Build-configuration difference.
    BuildConfigurationDifference,
    /// Version-specific upstream behavior.
    VersionSpecificUpstreamBehavior,
    /// Permitted protobuf nondeterminism.
    PermittedNondeterminism,
    /// Behavior the specification leaves unspecified.
    UnspecifiedBehavior,
    /// The upstream implementation itself misbehaves.
    UpstreamDefect,
    /// Intentional incompatibility, approved and documented.
    IntentionalIncompatibility,
}

impl ResidualClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResidualClass::RustDefect => "rust_defect",
            ResidualClass::IncompleteOracleModel => "incomplete_oracle_model",
            ResidualClass::PlatformDifference => "platform_difference",
            ResidualClass::BuildConfigurationDifference => "build_configuration_difference",
            ResidualClass::VersionSpecificUpstreamBehavior => "version_specific_upstream_behavior",
            ResidualClass::PermittedNondeterminism => "permitted_nondeterminism",
            ResidualClass::UnspecifiedBehavior => "unspecified_behavior",
            ResidualClass::UpstreamDefect => "upstream_defect",
            ResidualClass::IntentionalIncompatibility => "intentional_incompatibility",
        }
    }
}

/// Metadata recorded for every casefile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMetadata {
    pub id: String,
    pub court: String,
    /// Upstream commit SHA the oracle was built from.
    pub oracle: String,
    pub op: String,
    pub input_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u64>,
    /// Corpus generator seed that reproduces this case.
    pub seed: u64,
    /// Residual classification; None while the residual is still being
    /// explained.
    pub classification: Option<ResidualClass>,
    pub date: String,
    pub notes: String,
}

/// The comparison result for a single case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub oracle: serde_json::Value,
    pub dut: serde_json::Value,
    /// True when oracle and DUT agree exactly.
    pub equal: bool,
}

/// A residual record: a case where the DUT diverged from the oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualRecord {
    pub metadata: CaseMetadata,
    pub result: CaseResult,
    /// How the residual diverges, for quick triage.
    pub oracle_status: String,
    pub dut_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dut_value: Option<String>,
}

/// Summary of a court run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtSummary {
    pub court: String,
    pub oracle: String,
    pub total: u64,
    pub equal: u64,
    pub residuals: u64,
    pub corpus_version: String,
    pub rust_revision: String,
    pub date: String,
}

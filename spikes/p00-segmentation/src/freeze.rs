use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub const FROZEN_COMPONENT_COUNT: usize = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrozenComponentKind {
    ProviderSources,
    ProviderExecutables,
    ModelPack,
    Runtime,
    AdapterThresholds,
    SandboxProfile,
    CandidateRegistry,
    LicenseBlockerEvidence,
    Evaluator,
    DatasetGenerator,
    MetricOracle,
    HoldoutDeriver,
    EvidenceWriter,
    Schemas,
    Specifications,
    SourceTree,
    DependenciesToolchain,
    HostAttestation,
}

pub const ALL_FROZEN_COMPONENTS: [FrozenComponentKind; FROZEN_COMPONENT_COUNT] = [
    FrozenComponentKind::ProviderSources,
    FrozenComponentKind::ProviderExecutables,
    FrozenComponentKind::ModelPack,
    FrozenComponentKind::Runtime,
    FrozenComponentKind::AdapterThresholds,
    FrozenComponentKind::SandboxProfile,
    FrozenComponentKind::CandidateRegistry,
    FrozenComponentKind::LicenseBlockerEvidence,
    FrozenComponentKind::Evaluator,
    FrozenComponentKind::DatasetGenerator,
    FrozenComponentKind::MetricOracle,
    FrozenComponentKind::HoldoutDeriver,
    FrozenComponentKind::EvidenceWriter,
    FrozenComponentKind::Schemas,
    FrozenComponentKind::Specifications,
    FrozenComponentKind::SourceTree,
    FrozenComponentKind::DependenciesToolchain,
    FrozenComponentKind::HostAttestation,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenComponent {
    pub kind: FrozenComponentKind,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct SignerBinding {
    pub role: String,
    pub key_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstantiveManifest {
    pub schema_version: u32,
    pub components: Vec<FrozenComponent>,
    pub signer_bindings: Vec<SignerBinding>,
    pub signed_decision_payload_hashes: Vec<String>,
}

impl SubstantiveManifest {
    pub fn validate(&self) -> Result<(), FreezeError> {
        if self.schema_version != 1 {
            return Err(FreezeError::UnsupportedSchema);
        }
        if self.components.len() != FROZEN_COMPONENT_COUNT {
            return Err(FreezeError::ComponentCount);
        }
        let kinds = self
            .components
            .iter()
            .map(|component| component.kind)
            .collect::<BTreeSet<_>>();
        if kinds.len() != FROZEN_COMPONENT_COUNT
            || ALL_FROZEN_COMPONENTS
                .iter()
                .any(|kind| !kinds.contains(kind))
        {
            return Err(FreezeError::ComponentSet);
        }
        for component in &self.components {
            validate_digest(&component.sha256)?;
        }
        if self.signer_bindings.is_empty()
            || self
                .signer_bindings
                .iter()
                .any(|binding| binding.role.is_empty() || binding.key_fingerprint.is_empty())
        {
            return Err(FreezeError::SignerBinding);
        }
        if self.signed_decision_payload_hashes.is_empty() {
            return Err(FreezeError::DecisionPayload);
        }
        for digest in &self.signed_decision_payload_hashes {
            validate_digest(digest)?;
        }
        Ok(())
    }

    pub fn substantive_identity(&self) -> Result<String, FreezeError> {
        self.validate()?;
        let mut components = self.components.clone();
        components.sort_by_key(|component| component.kind);
        let mut signers = self.signer_bindings.clone();
        signers.sort();
        let mut decisions = self.signed_decision_payload_hashes.clone();
        decisions.sort();

        let mut canonical = Vec::new();
        append_field(&mut canonical, b"p00-seg-substantive-identity-v1");
        append_field(&mut canonical, &self.schema_version.to_be_bytes());
        for component in components {
            append_field(&mut canonical, format!("{:?}", component.kind).as_bytes());
            append_field(&mut canonical, component.sha256.as_bytes());
        }
        for signer in signers {
            append_field(&mut canonical, signer.role.as_bytes());
            append_field(&mut canonical, signer.key_fingerprint.as_bytes());
        }
        for decision in decisions {
            append_field(&mut canonical, decision.as_bytes());
        }
        Ok(sha256_hex(&canonical))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEnvelope {
    pub freeze_instance_id: String,
    pub nonce_commitment: String,
    pub randomness_commitment: Option<String>,
    pub raw_signature: String,
    pub timestamp_ms: i64,
    pub ledger_sequence: u64,
    pub ledger_offset: u64,
    pub ledger_head_hash: String,
    pub status_label: String,
    pub request_handles: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseKind {
    AcceptanceRoot,
    Supplemental,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseStatus {
    Reserved,
    Completed(ReleaseAssessment),
    Failed,
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAssessment {
    pub expected_cases: usize,
    pub truths: usize,
    pub warm_calls: usize,
    pub repeated_negative_calls: usize,
    pub automatic_gates_pass: bool,
    pub cold_pass: bool,
    pub peak_memory_bytes: u64,
    pub package_bytes: u64,
    pub cold_latency_ms: u64,
}

impl ReleaseAssessment {
    fn complete_and_passing(&self) -> bool {
        self.expected_cases == 256
            && self.truths == 320
            && self.warm_calls == 768
            && self.repeated_negative_calls == 96
            && self.automatic_gates_pass
            && self.cold_pass
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortRelease {
    pub freeze_instance_id: String,
    pub release_id: String,
    pub kind: ReleaseKind,
    pub status: ReleaseStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryCohort {
    substantive_identity: String,
    releases: Vec<CohortRelease>,
    closed: bool,
}

impl RetryCohort {
    pub fn new(substantive_identity: String) -> Result<Self, FreezeError> {
        validate_digest(&substantive_identity)?;
        Ok(Self {
            substantive_identity,
            releases: Vec::new(),
            closed: false,
        })
    }

    pub fn substantive_identity(&self) -> &str {
        &self.substantive_identity
    }

    pub fn releases(&self) -> &[CohortRelease] {
        &self.releases
    }

    pub fn allocate(
        &mut self,
        freeze_instance_id: impl Into<String>,
        release_id: impl Into<String>,
    ) -> Result<ReleaseKind, FreezeError> {
        if self.closed {
            return Err(FreezeError::IdentityClosed);
        }
        let freeze_instance_id = freeze_instance_id.into();
        let release_id = release_id.into();
        if freeze_instance_id.is_empty() || release_id.is_empty() {
            return Err(FreezeError::EmptyReleaseIdentity);
        }
        if self.releases.iter().any(|release| {
            release.freeze_instance_id == freeze_instance_id || release.release_id == release_id
        }) {
            return Err(FreezeError::DuplicateRelease);
        }
        let kind = if self.releases.is_empty() {
            ReleaseKind::AcceptanceRoot
        } else {
            ReleaseKind::Supplemental
        };
        self.releases.push(CohortRelease {
            freeze_instance_id,
            release_id,
            kind,
            status: ReleaseStatus::Reserved,
        });
        Ok(kind)
    }

    pub fn set_status(
        &mut self,
        freeze_instance_id: &str,
        status: ReleaseStatus,
    ) -> Result<(), FreezeError> {
        let release = self
            .releases
            .iter_mut()
            .find(|release| release.freeze_instance_id == freeze_instance_id)
            .ok_or(FreezeError::UnknownRelease)?;
        if !matches!(release.status, ReleaseStatus::Reserved) {
            return Err(FreezeError::TerminalRelease);
        }
        release.status = status;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), FreezeError> {
        if self.closed {
            return Err(FreezeError::IdentityClosed);
        }
        self.closed = true;
        Ok(())
    }

    pub fn conservative_assessment(&self) -> CohortAssessment {
        let completed = self
            .releases
            .iter()
            .filter_map(|release| match &release.status {
                ReleaseStatus::Completed(assessment) => Some(assessment),
                _ => None,
            })
            .collect::<Vec<_>>();
        let all_releases_pass = self.closed
            && !self.releases.is_empty()
            && completed.len() == self.releases.len()
            && completed
                .iter()
                .all(|assessment| assessment.complete_and_passing());
        CohortAssessment {
            acceptance_eligible: all_releases_pass,
            release_count: self.releases.len(),
            pooled_expected_cases: completed.len() * 256,
            pooled_truths: completed.len() * 960,
            pooled_warm_calls: completed.iter().map(|value| value.warm_calls).sum(),
            pooled_repeated_negative_calls: completed
                .iter()
                .map(|value| value.repeated_negative_calls)
                .sum(),
            worst_peak_memory_bytes: completed.iter().map(|value| value.peak_memory_bytes).max(),
            worst_package_bytes: completed.iter().map(|value| value.package_bytes).max(),
            worst_cold_latency_ms: completed.iter().map(|value| value.cold_latency_ms).max(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortAssessment {
    pub acceptance_eligible: bool,
    pub release_count: usize,
    pub pooled_expected_cases: usize,
    pub pooled_truths: usize,
    pub pooled_warm_calls: usize,
    pub pooled_repeated_negative_calls: usize,
    pub worst_peak_memory_bytes: Option<u64>,
    pub worst_package_bytes: Option<u64>,
    pub worst_cold_latency_ms: Option<u64>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn validate_digest(value: &str) -> Result<(), FreezeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FreezeError::InvalidDigest);
    }
    Ok(())
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_be_bytes());
    output.extend_from_slice(field);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreezeError {
    UnsupportedSchema,
    ComponentCount,
    ComponentSet,
    InvalidDigest,
    SignerBinding,
    DecisionPayload,
    IdentityClosed,
    EmptyReleaseIdentity,
    DuplicateRelease,
    UnknownRelease,
    TerminalRelease,
}

impl fmt::Display for FreezeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for FreezeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn manifest() -> SubstantiveManifest {
        SubstantiveManifest {
            schema_version: 1,
            components: ALL_FROZEN_COMPONENTS
                .iter()
                .enumerate()
                .map(|(index, kind)| FrozenComponent {
                    kind: *kind,
                    sha256: digest(&format!("component-{index}")),
                })
                .collect(),
            signer_bindings: vec![SignerBinding {
                role: "evaluator".into(),
                key_fingerprint: "fingerprint-1".into(),
            }],
            signed_decision_payload_hashes: vec![digest("decision")],
        }
    }

    fn passing_assessment() -> ReleaseAssessment {
        ReleaseAssessment {
            expected_cases: 256,
            truths: 320,
            warm_calls: 768,
            repeated_negative_calls: 96,
            automatic_gates_pass: true,
            cold_pass: true,
            peak_memory_bytes: 100,
            package_bytes: 200,
            cold_latency_ms: 300,
        }
    }

    #[test]
    fn every_frozen_component_is_substantive() {
        let baseline = manifest().substantive_identity().unwrap();
        for index in 0..FROZEN_COMPONENT_COUNT {
            let mut changed = manifest();
            changed.components[index].sha256 = digest(&format!("mutated-{index}"));
            assert_ne!(changed.substantive_identity().unwrap(), baseline);
        }
    }

    #[test]
    fn identity_is_order_independent_but_signer_binding_is_substantive() {
        let baseline = manifest().substantive_identity().unwrap();
        let mut reordered = manifest();
        reordered.components.reverse();
        assert_eq!(reordered.substantive_identity().unwrap(), baseline);

        let mut changed = manifest();
        changed.signer_bindings[0].key_fingerprint.push_str("-new");
        assert_ne!(changed.substantive_identity().unwrap(), baseline);
    }

    #[test]
    fn release_nonce_signature_time_and_handles_are_identity_independent() {
        let identity = manifest().substantive_identity().unwrap();
        let first = ReleaseEnvelope {
            freeze_instance_id: "freeze-a".into(),
            nonce_commitment: digest("nonce-a"),
            randomness_commitment: Some(digest("random-a")),
            raw_signature: "signature-a".into(),
            timestamp_ms: 1,
            ledger_sequence: 1,
            ledger_offset: 10,
            ledger_head_hash: digest("head-a"),
            status_label: "reserved".into(),
            request_handles: vec!["handle-a".into()],
        };
        let mut second = first.clone();
        second.nonce_commitment = digest("nonce-b");
        second.raw_signature = "signature-b".into();
        second.timestamp_ms = 999;
        second.ledger_sequence = 77;
        second.status_label = "completed".into();
        assert_ne!(first, second);
        assert_eq!(manifest().substantive_identity().unwrap(), identity);
    }

    #[test]
    fn retries_share_one_root_and_are_conservatively_aggregated() {
        let mut cohort = RetryCohort::new(manifest().substantive_identity().unwrap()).unwrap();
        assert_eq!(
            cohort.allocate("freeze-1", "release-1").unwrap(),
            ReleaseKind::AcceptanceRoot
        );
        cohort
            .set_status("freeze-1", ReleaseStatus::Completed(passing_assessment()))
            .unwrap();
        assert_eq!(
            cohort.allocate("freeze-2", "release-2").unwrap(),
            ReleaseKind::Supplemental
        );
        let mut second = passing_assessment();
        second.peak_memory_bytes = 500;
        cohort
            .set_status("freeze-2", ReleaseStatus::Completed(second))
            .unwrap();
        cohort.close().unwrap();
        let assessment = cohort.conservative_assessment();
        assert!(assessment.acceptance_eligible);
        assert_eq!(assessment.pooled_warm_calls, 1_536);
        assert_eq!(assessment.pooled_truths, 1_920);
        assert_eq!(assessment.worst_peak_memory_bytes, Some(500));
        assert_eq!(
            cohort.allocate("freeze-3", "release-3"),
            Err(FreezeError::IdentityClosed)
        );
    }

    #[test]
    fn failed_abandoned_or_incomplete_retry_poisons_the_identity() {
        for terminal in [ReleaseStatus::Failed, ReleaseStatus::Abandoned] {
            let mut cohort = RetryCohort::new(manifest().substantive_identity().unwrap()).unwrap();
            cohort.allocate("freeze-1", "release-1").unwrap();
            cohort.set_status("freeze-1", terminal).unwrap();
            cohort.close().unwrap();
            assert!(!cohort.conservative_assessment().acceptance_eligible);
        }

        let mut cohort = RetryCohort::new(manifest().substantive_identity().unwrap()).unwrap();
        cohort.allocate("freeze-1", "release-1").unwrap();
        cohort
            .set_status("freeze-1", ReleaseStatus::Completed(passing_assessment()))
            .unwrap();
        cohort.allocate("freeze-2", "release-2").unwrap();
        cohort.close().unwrap();
        assert!(!cohort.conservative_assessment().acceptance_eligible);
    }

    #[test]
    fn duplicate_freeze_or_release_cannot_allocate_again() {
        let mut cohort = RetryCohort::new(manifest().substantive_identity().unwrap()).unwrap();
        cohort.allocate("freeze-1", "release-1").unwrap();
        assert_eq!(
            cohort.allocate("freeze-1", "release-2"),
            Err(FreezeError::DuplicateRelease)
        );
        assert_eq!(
            cohort.allocate("freeze-2", "release-1"),
            Err(FreezeError::DuplicateRelease)
        );
    }
}

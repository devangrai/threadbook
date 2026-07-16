use crate::fallback::FALLBACK_ID;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const AUTOMATIC_CANDIDATE_ID: &str = "coreml_garment_provider_slot_v1";
pub const REVIEW_BLOCKER: &str = "reviewed_model_pack_absent";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRole {
    PlannedProviderSlot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateAvailability {
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMetrics {
    pub recall_millionths: u32,
    pub mean_iou_millionths: u32,
    pub warm_p95_ms: u64,
    pub peak_memory_bytes: u64,
    pub package_bytes: u64,
    pub failures: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateDescriptor {
    pub candidate_id: String,
    pub role: CandidateRole,
    pub availability: CandidateAvailability,
    pub reason: String,
    pub invocations: u64,
    pub source_locator: Option<String>,
    pub model_revision: Option<String>,
    pub license_decision: Option<String>,
    pub measurements: Option<RuntimeMetrics>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRegistry {
    pub schema_version: u32,
    pub candidates: Vec<CandidateDescriptor>,
    pub fallback_selected: String,
}

impl CandidateRegistry {
    pub fn reviewed_state() -> Self {
        Self {
            schema_version: 1,
            candidates: vec![CandidateDescriptor {
                candidate_id: AUTOMATIC_CANDIDATE_ID.into(),
                role: CandidateRole::PlannedProviderSlot,
                availability: CandidateAvailability::Unavailable,
                reason: REVIEW_BLOCKER.into(),
                invocations: 0,
                source_locator: None,
                model_revision: None,
                license_decision: None,
                measurements: None,
            }],
            fallback_selected: FALLBACK_ID.into(),
        }
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != 1 {
            return Err(RegistryError::UnsupportedSchema);
        }
        if self.fallback_selected != FALLBACK_ID {
            return Err(RegistryError::Fallback);
        }
        if self.candidates.len() != 1 {
            return Err(RegistryError::PlannedSlotCount);
        }

        let candidate = &self.candidates[0];
        if candidate.candidate_id != AUTOMATIC_CANDIDATE_ID
            || candidate.role != CandidateRole::PlannedProviderSlot
            || candidate.availability != CandidateAvailability::Unavailable
            || candidate.reason != REVIEW_BLOCKER
            || candidate.invocations != 0
            || candidate.source_locator.is_some()
            || candidate.model_revision.is_some()
            || candidate.license_decision.is_some()
            || candidate.measurements.is_some()
        {
            return Err(RegistryError::PlannedSlotEvidence);
        }
        Ok(())
    }

    pub fn automatic_candidates(&self) -> usize {
        0
    }

    pub fn automatic_eligible(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    UnsupportedSchema,
    Fallback,
    PlannedSlotCount,
    PlannedSlotEvidence,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_slot_is_unavailable_without_fabricated_metadata() {
        let registry = CandidateRegistry::reviewed_state();
        assert_eq!(registry.validate(), Ok(()));
        assert_eq!(registry.automatic_candidates(), 0);
        assert!(!registry.automatic_eligible());

        let candidate = &registry.candidates[0];
        assert_eq!(candidate.candidate_id, AUTOMATIC_CANDIDATE_ID);
        assert_eq!(candidate.role, CandidateRole::PlannedProviderSlot);
        assert_eq!(candidate.availability, CandidateAvailability::Unavailable);
        assert_eq!(candidate.reason, REVIEW_BLOCKER);
        assert_eq!(candidate.invocations, 0);
        assert_eq!(candidate.source_locator, None);
        assert_eq!(candidate.model_revision, None);
        assert_eq!(candidate.license_decision, None);
        assert_eq!(candidate.measurements, None);
    }

    #[test]
    fn rejects_missing_or_fabricated_planned_slot_data() {
        let mut missing = CandidateRegistry::reviewed_state();
        missing.candidates.clear();
        assert_eq!(missing.validate(), Err(RegistryError::PlannedSlotCount));

        let mut source = CandidateRegistry::reviewed_state();
        source.candidates[0].source_locator = Some("https://example.invalid/model".into());
        assert_eq!(source.validate(), Err(RegistryError::PlannedSlotEvidence));

        let mut measurements = CandidateRegistry::reviewed_state();
        measurements.candidates[0].measurements = Some(RuntimeMetrics {
            recall_millionths: 0,
            mean_iou_millionths: 0,
            warm_p95_ms: 0,
            peak_memory_bytes: 0,
            package_bytes: 0,
            failures: 0,
        });
        assert_eq!(
            measurements.validate(),
            Err(RegistryError::PlannedSlotEvidence)
        );
    }
}

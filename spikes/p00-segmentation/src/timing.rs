use crate::contract::{validate_outcome, InferenceRequest, SegmentationOutcome};
use crate::freeze::sha256_hex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallIdentity {
    pub substantive_identity: String,
    pub freeze_instance_id: String,
    pub release_id: String,
    pub provider_revision: String,
    pub request_handle: String,
    pub call_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingRecord {
    pub schema_version: u32,
    pub substantive_identity: String,
    pub freeze_instance_id: String,
    pub release_id: String,
    pub provider_revision: String,
    pub request_handle: String,
    pub call_ordinal: u64,
    pub start_ticks: u64,
    pub end_ticks: u64,
    pub duration_ticks: u64,
    pub validation_status: String,
    pub output_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreRecord {
    pub schema_version: u32,
    pub output_hash: String,
    pub score_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedArtifact {
    bound_output: Vec<u8>,
    output_hash: String,
}

impl TimedArtifact {
    pub fn bound_output(&self) -> &[u8] {
        &self.bound_output
    }

    pub fn output_hash(&self) -> &str {
        &self.output_hash
    }

    pub fn verify(&self) -> bool {
        sha256_hex(&self.bound_output) == self.output_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedScore {
    pub timing: TimingRecord,
    pub artifact: TimedArtifact,
    pub score: ScoreRecord,
}

pub trait MonotonicClock {
    fn ticks(&self) -> u64;
}

#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn ticks(&self) -> u64 {
        self.origin.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
    }
}

pub fn time_validate_hash_then_score<C, I, S>(
    clock: &C,
    identity: CallIdentity,
    request: &InferenceRequest,
    invoke: I,
    score_outside_timer: S,
) -> Result<TimedScore, TimingError>
where
    C: MonotonicClock,
    I: FnOnce() -> Vec<u8>,
    S: FnOnce(&TimedArtifact) -> Vec<u8>,
{
    let start_ticks = clock.ticks();
    let received = invoke();
    let (bound_output, validation_status) =
        match serde_json::from_slice::<SegmentationOutcome>(&received) {
            Ok(parsed) => match validate_outcome(&parsed, request) {
                Ok(()) => (
                    serde_json::to_vec(&parsed).map_err(TimingError::OutputSerialize)?,
                    "valid",
                ),
                Err(_) => (
                    canonical_failure_binding("invalid_output", &received)?,
                    "invalid_output",
                ),
            },
            Err(_) => (
                canonical_failure_binding("invalid_json", &received)?,
                "invalid_json",
            ),
        };
    let output_hash = sha256_hex(&bound_output);
    let end_ticks = clock.ticks();
    let duration_ticks = end_ticks
        .checked_sub(start_ticks)
        .ok_or(TimingError::NonMonotonicClock)?;

    let timing = TimingRecord {
        schema_version: 1,
        substantive_identity: identity.substantive_identity,
        freeze_instance_id: identity.freeze_instance_id,
        release_id: identity.release_id,
        provider_revision: identity.provider_revision,
        request_handle: identity.request_handle,
        call_ordinal: identity.call_ordinal,
        start_ticks,
        end_ticks,
        duration_ticks,
        validation_status: validation_status.into(),
        output_hash: output_hash.clone(),
    };
    let artifact = TimedArtifact {
        bound_output,
        output_hash: output_hash.clone(),
    };

    // Hidden truth is only available to this closure, after the end tick is sampled.
    let score_payload = score_outside_timer(&artifact);
    let score = ScoreRecord {
        schema_version: 1,
        output_hash,
        score_hash: sha256_hex(&score_payload),
    };
    let result = TimedScore {
        timing,
        artifact,
        score,
    };
    verify_timing_score_binding(&result)?;
    Ok(result)
}

#[derive(Serialize)]
struct FailureBinding<'a> {
    schema_version: u32,
    failure: &'a str,
    received_bytes_sha256: String,
}

fn canonical_failure_binding(failure: &str, received: &[u8]) -> Result<Vec<u8>, TimingError> {
    serde_json::to_vec(&FailureBinding {
        schema_version: 1,
        failure,
        received_bytes_sha256: sha256_hex(received),
    })
    .map_err(TimingError::OutputSerialize)
}

pub fn verify_timing_score_binding(result: &TimedScore) -> Result<(), TimingError> {
    if result.timing.schema_version != 1 || result.score.schema_version != 1 {
        return Err(TimingError::UnsupportedSchema);
    }
    if result.timing.end_ticks < result.timing.start_ticks
        || result.timing.duration_ticks != result.timing.end_ticks - result.timing.start_ticks
    {
        return Err(TimingError::DurationMutation);
    }
    if !result.artifact.verify()
        || result.timing.output_hash != result.artifact.output_hash
        || result.score.output_hash != result.artifact.output_hash
    {
        return Err(TimingError::OutputHashMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub enum TimingError {
    OutputSerialize(serde_json::Error),
    NonMonotonicClock,
    UnsupportedSchema,
    DurationMutation,
    OutputHashMismatch,
}

impl PartialEq for TimingError {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for TimingError {}

impl fmt::Display for TimingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for TimingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{InferenceMode, PixelBuffer, RequestHandle};
    use std::cell::Cell;

    #[derive(Default)]
    struct ManualClock(Cell<u64>);

    impl ManualClock {
        fn advance(&self, ticks: u64) {
            self.0.set(self.0.get() + ticks);
        }
    }

    impl MonotonicClock for ManualClock {
        fn ticks(&self) -> u64 {
            self.0.get()
        }
    }

    fn request() -> InferenceRequest {
        InferenceRequest::new(
            RequestHandle::parse("timing-request-01").unwrap(),
            PixelBuffer::new(2, 2, vec![0; 12]).unwrap(),
            InferenceMode::FullImage,
        )
        .unwrap()
    }

    fn identity() -> CallIdentity {
        CallIdentity {
            substantive_identity: "identity".into(),
            freeze_instance_id: "freeze".into(),
            release_id: "release".into(),
            provider_revision: "provider".into(),
            request_handle: "timing-request-01".into(),
            call_ordinal: 7,
        }
    }

    #[test]
    fn timer_binds_validated_canonical_output_and_excludes_truth_scoring() {
        let clock = ManualClock::default();
        let result = time_validate_hash_then_score(
            &clock,
            identity(),
            &request(),
            || {
                clock.advance(40);
                serde_json::to_vec(&SegmentationOutcome::NoGarment).unwrap()
            },
            |artifact| {
                assert!(artifact.verify());
                clock.advance(10_000);
                b"hidden-truth-score".to_vec()
            },
        )
        .unwrap();
        assert_eq!(result.timing.start_ticks, 0);
        assert_eq!(result.timing.end_ticks, 40);
        assert_eq!(result.timing.duration_ticks, 40);
        assert_eq!(clock.ticks(), 10_040);
        assert_eq!(result.timing.output_hash, result.score.output_hash);
    }

    #[test]
    fn output_mutation_hash_swap_and_duration_mutation_are_rejected() {
        let clock = ManualClock::default();
        let result = time_validate_hash_then_score(
            &clock,
            identity(),
            &request(),
            || serde_json::to_vec(&SegmentationOutcome::NoGarment).unwrap(),
            |_| Vec::new(),
        )
        .unwrap();

        let mut mutated = result.clone();
        mutated.artifact.bound_output.push(b' ');
        assert_eq!(
            verify_timing_score_binding(&mutated),
            Err(TimingError::OutputHashMismatch)
        );

        let mut swapped = result.clone();
        swapped.score.output_hash = sha256_hex(b"different call");
        assert_eq!(
            verify_timing_score_binding(&swapped),
            Err(TimingError::OutputHashMismatch)
        );

        let mut altered_duration = result;
        altered_duration.timing.duration_ticks += 1;
        assert_eq!(
            verify_timing_score_binding(&altered_duration),
            Err(TimingError::DurationMutation)
        );
    }

    #[test]
    fn malformed_and_invalid_outputs_are_timed_bound_and_failure_scored() {
        let clock = ManualClock::default();
        let malformed = time_validate_hash_then_score(
            &clock,
            identity(),
            &request(),
            || b"not-json".to_vec(),
            |artifact| artifact.output_hash().as_bytes().to_vec(),
        )
        .unwrap();
        assert_eq!(malformed.timing.validation_status, "invalid_json");
        assert_eq!(malformed.timing.output_hash, malformed.score.output_hash);

        let zero_masks = br#"{"outcome":"masks","masks":[]}"#.to_vec();
        let invalid = time_validate_hash_then_score(
            &clock,
            identity(),
            &request(),
            || zero_masks,
            |artifact| artifact.output_hash().as_bytes().to_vec(),
        )
        .unwrap();
        assert_eq!(invalid.timing.validation_status, "invalid_output");
        assert!(invalid.artifact.verify());
    }
}

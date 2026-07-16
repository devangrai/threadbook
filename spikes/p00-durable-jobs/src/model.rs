use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewJob {
    pub id: String,
    pub idempotency_key: String,
    pub kind: String,
    pub payload_version: i64,
    pub payload: Value,
    pub normalized_input_hash: String,
    pub pipeline_version: String,
}

impl NewJob {
    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, value) in [
            ("id", self.id.as_str()),
            ("idempotency_key", self.idempotency_key.as_str()),
            ("kind", self.kind.as_str()),
            ("normalized_input_hash", self.normalized_input_hash.as_str()),
            ("pipeline_version", self.pipeline_version.as_str()),
        ] {
            if value.is_empty() {
                return Err(ModelError::EmptyField(field));
            }
        }
        if self.payload_version < 1 {
            return Err(ModelError::InvalidPayloadVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasedJob {
    pub job: NewJob,
    pub attempt: i64,
    pub lease_owner: String,
    pub lease_expires_at_ms: i64,
    pub fence: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobOutput {
    pub output_key: String,
    pub result_hash: String,
    pub output: Value,
}

impl JobOutput {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.output_key.is_empty() {
            return Err(ModelError::EmptyField("output_key"));
        }
        if self.result_hash.is_empty() {
            return Err(ModelError::EmptyField("result_hash"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Enqueued,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutcome {
    Committed,
    AlreadyCommitted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    EmptyField(&'static str),
    InvalidPayloadVersion,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::InvalidPayloadVersion => write!(formatter, "payload_version must be positive"),
        }
    }
}

impl Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn job() -> NewJob {
        NewJob {
            id: "job-1".into(),
            idempotency_key: "request-1".into(),
            kind: "thumbnail".into(),
            payload_version: 1,
            payload: json!({"asset": "a"}),
            normalized_input_hash: "input-hash".into(),
            pipeline_version: "pipeline-v1".into(),
        }
    }

    #[test]
    fn validates_job_envelope() {
        assert_eq!(job().validate(), Ok(()));

        let mut invalid = job();
        invalid.id.clear();
        assert_eq!(invalid.validate(), Err(ModelError::EmptyField("id")));

        let mut invalid = job();
        invalid.payload_version = 0;
        assert_eq!(invalid.validate(), Err(ModelError::InvalidPayloadVersion));
    }

    #[test]
    fn validates_output_identity() {
        let output = JobOutput {
            output_key: "output-1".into(),
            result_hash: "result-hash".into(),
            output: json!({"ok": true}),
        };
        assert_eq!(output.validate(), Ok(()));
    }
}

use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{require_schema_v1, validate_timestamp};
use crate::{
    deserialize_schema_version_v1, RequestId, SafeFieldV1, Sha256Digest, Validate, ValidationError,
    MAX_SAFE_INTEGER_V1,
};

pub const MAX_BACKUP_PAGE_SIZE: u16 = 100;
pub const MAX_BACKUP_CURSOR_CHARS: usize = 512;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
pub struct BackupId(#[ts(type = "string")] Uuid);

impl BackupId {
    pub fn new(value: Uuid) -> Result<Self, &'static str> {
        if value.is_nil() {
            Err("UUID must not be nil")
        } else {
            Ok(Self(value))
        }
    }

    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for BackupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for BackupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl Serialize for BackupId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BackupId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BackupIdVisitor;

        impl<'de> Visitor<'de> for BackupIdVisitor {
            type Value = BackupId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical non-nil UUID string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 36 {
                    return Err(E::custom("UUID must use canonical hyphenated form"));
                }
                let parsed = Uuid::parse_str(value).map_err(|_| E::custom("invalid UUID"))?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(E::custom("UUID must be canonical and non-nil"));
                }
                Ok(BackupId(parsed))
            }
        }

        deserializer.deserialize_str(BackupIdVisitor)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(transparent)]
pub struct BackupPageCursorV1(String);

impl BackupPageCursorV1 {
    pub fn new(value: String) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.chars().count() > MAX_BACKUP_CURSOR_CHARS
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(ValidationError::new(SafeFieldV1::Cursor));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BackupPageCursorV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| D::Error::custom("invalid backup page cursor"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum BackupReasonV1 {
    Manual,
    Scheduled,
    PreUpgrade,
    PreRestore,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct BackupRecordV1 {
    pub backup_id: BackupId,
    pub reason: BackupReasonV1,
    pub created_at: String,
    pub expires_at: String,
    pub manifest_sha256: Sha256Digest,
    pub database_schema_version: u32,
    #[ts(type = "number")]
    pub asset_count: u64,
    #[ts(type = "number")]
    pub total_bytes: u64,
}

impl Validate for BackupRecordV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_timestamp(&self.created_at)?;
        validate_timestamp(&self.expires_at)?;
        if self.expires_at <= self.created_at {
            return Err(ValidationError::new(SafeFieldV1::Timestamp));
        }
        if self.asset_count >= MAX_SAFE_INTEGER_V1
            || self.total_bytes == 0
            || self.total_bytes >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub reason: BackupReasonV1,
}

impl Validate for CreateBackupV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.reason == BackupReasonV1::Manual {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RequestId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListBackupsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub cursor: Option<BackupPageCursorV1>,
    pub limit: u16,
}

impl Validate for ListBackupsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if (1..=MAX_BACKUP_PAGE_SIZE).contains(&self.limit) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Limit))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PrepareRestoreV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub backup_id: BackupId,
    pub expected_manifest_sha256: Sha256Digest,
}

impl Validate for PrepareRestoreV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub backup: BackupRecordV1,
}

impl Validate for CreateBackupV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.backup.validate()?;
        if self.backup.reason == BackupReasonV1::Manual {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RequestId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListBackupsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub backups: Vec<BackupRecordV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    pub next_cursor: Option<BackupPageCursorV1>,
}

impl Validate for ListBackupsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.backups.len() > MAX_BACKUP_PAGE_SIZE as usize
            || self.total_count < self.backups.len() as u64
            || self.total_count >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        self.backups.iter().try_for_each(Validate::validate)?;
        if self.backups.windows(2).any(|pair| {
            pair[0].created_at < pair[1].created_at
                || (pair[0].created_at == pair[1].created_at
                    && pair[0].backup_id <= pair[1].backup_id)
        }) {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        if self.backups.is_empty() && self.next_cursor.is_some() {
            return Err(ValidationError::new(SafeFieldV1::Cursor));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PrepareRestoreV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub restart_required: bool,
    pub safety_backup_id: BackupId,
}

impl Validate for PrepareRestoreV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.restart_required {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RequestId))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::SCHEMA_VERSION_V1;

    fn backup(reason: BackupReasonV1, created_at: &str, backup_id: &str) -> BackupRecordV1 {
        BackupRecordV1 {
            backup_id: serde_json::from_value(json!(backup_id)).unwrap(),
            reason,
            created_at: created_at.to_owned(),
            expires_at: "2026-09-01T00:00:00Z".to_owned(),
            manifest_sha256: Sha256Digest::parse("a".repeat(64)).unwrap(),
            database_schema_version: 9,
            asset_count: 12,
            total_bytes: 4096,
        }
    }

    fn assert_no_path_fields(value: &Value) {
        match value {
            Value::Object(fields) => {
                assert!(fields.keys().all(|key| !key.contains("path")));
                fields.values().for_each(assert_no_path_fields);
            }
            Value::Array(values) => values.iter().for_each(assert_no_path_fields),
            _ => {}
        }
    }

    #[test]
    fn backup_ids_are_canonical_non_nil_uuids() {
        assert!(
            serde_json::from_value::<BackupId>(json!("123e4567-e89b-12d3-a456-426614174000"))
                .is_ok()
        );
        assert!(
            serde_json::from_value::<BackupId>(json!("123E4567-E89B-12D3-A456-426614174000"))
                .is_err()
        );
        assert!(
            serde_json::from_value::<BackupId>(json!("00000000-0000-0000-0000-000000000000"))
                .is_err()
        );
    }

    #[test]
    fn create_backup_is_manual_only_and_strict() {
        let request_id = RequestId::new_v4().to_string();
        let manual: CreateBackupV1Request = serde_json::from_value(json!({
            "schema_version": 1,
            "request_id": request_id,
            "reason": "manual"
        }))
        .unwrap();
        assert!(manual.validate().is_ok());

        let scheduled: CreateBackupV1Request = serde_json::from_value(json!({
            "schema_version": 1,
            "request_id": RequestId::new_v4().to_string(),
            "reason": "scheduled"
        }))
        .unwrap();
        assert!(scheduled.validate().is_err());

        assert!(serde_json::from_value::<CreateBackupV1Request>(json!({
            "schema_version": 1,
            "request_id": RequestId::new_v4().to_string(),
            "reason": "manual",
            "path": "/tmp/export"
        }))
        .is_err());
    }

    #[test]
    fn list_request_bounds_limit_and_cursor() {
        for limit in [1, MAX_BACKUP_PAGE_SIZE] {
            let request = ListBackupsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                cursor: Some(BackupPageCursorV1::new("opaque-token".to_owned()).unwrap()),
                limit,
            };
            assert!(request.validate().is_ok());
        }

        for limit in [0, MAX_BACKUP_PAGE_SIZE + 1] {
            let request = ListBackupsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                cursor: None,
                limit,
            };
            assert!(request.validate().is_err());
        }

        assert!(BackupPageCursorV1::new(String::new()).is_err());
        assert!(BackupPageCursorV1::new("x".repeat(MAX_BACKUP_CURSOR_CHARS + 1)).is_err());
        assert!(BackupPageCursorV1::new("line\nbreak".to_owned()).is_err());
    }

    #[test]
    fn backup_records_are_bounded_and_expire_after_creation() {
        let mut record = backup(
            BackupReasonV1::Manual,
            "2026-07-15T11:03:00Z",
            "123e4567-e89b-12d3-a456-426614174000",
        );
        assert!(record.validate().is_ok());
        record.database_schema_version = 0;
        assert!(record.validate().is_ok());

        record.expires_at = record.created_at.clone();
        assert!(record.validate().is_err());
        record.expires_at = "2026-09-01T00:00:00Z".to_owned();
        record.asset_count = MAX_SAFE_INTEGER_V1;
        assert!(record.validate().is_err());
        record.asset_count = 0;
        record.total_bytes = 0;
        assert!(record.validate().is_err());
    }

    #[test]
    fn list_response_requires_stable_newest_first_unique_records() {
        let newer = backup(
            BackupReasonV1::Scheduled,
            "2026-07-16T11:03:00Z",
            "323e4567-e89b-12d3-a456-426614174000",
        );
        let older = backup(
            BackupReasonV1::PreUpgrade,
            "2026-07-15T11:03:00Z",
            "223e4567-e89b-12d3-a456-426614174000",
        );
        let mut response = ListBackupsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            backups: vec![newer, older],
            total_count: 2,
            next_cursor: None,
        };
        assert!(response.validate().is_ok());

        response.backups.reverse();
        assert!(response.validate().is_err());
        response.backups.reverse();
        response.backups[1] = response.backups[0].clone();
        assert!(response.validate().is_err());
    }

    #[test]
    fn restore_is_hash_bound_and_always_restart_bound() {
        let request: PrepareRestoreV1Request = serde_json::from_value(json!({
            "schema_version": 1,
            "request_id": RequestId::new_v4().to_string(),
            "backup_id": "123e4567-e89b-12d3-a456-426614174000",
            "expected_manifest_sha256": "b".repeat(64)
        }))
        .unwrap();
        assert!(request.validate().is_ok());

        assert!(serde_json::from_value::<PrepareRestoreV1Request>(json!({
            "schema_version": 1,
            "request_id": RequestId::new_v4().to_string(),
            "backup_id": "123e4567-e89b-12d3-a456-426614174000",
            "expected_manifest_sha256": "B".repeat(64)
        }))
        .is_err());

        let response = PrepareRestoreV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            restart_required: false,
            safety_backup_id: BackupId::new_v4(),
        };
        assert!(response.validate().is_err());
    }

    #[test]
    fn serialized_contracts_expose_no_filesystem_paths() {
        let create = CreateBackupV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            backup: backup(
                BackupReasonV1::Manual,
                "2026-07-15T11:03:00Z",
                "123e4567-e89b-12d3-a456-426614174000",
            ),
        };
        let restore = PrepareRestoreV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            restart_required: true,
            safety_backup_id: BackupId::new_v4(),
        };
        assert_no_path_fields(&serde_json::to_value(create).unwrap());
        assert_no_path_fields(&serde_json::to_value(restore).unwrap());
    }
}

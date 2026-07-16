use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{SafeFieldV1, SCHEMA_VERSION_V1};

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub field: SafeFieldV1,
}

impl ValidationError {
    pub const fn new(field: SafeFieldV1) -> Self {
        Self { field }
    }
}

pub(crate) fn require_schema_v1(version: u8) -> Result<(), ValidationError> {
    if version == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::SchemaVersion))
    }
}

pub(crate) fn validate_bounded_text(
    value: &str,
    min_chars: usize,
    max_chars: usize,
    field: SafeFieldV1,
) -> Result<(), ValidationError> {
    let char_count = value.chars().count();
    if char_count < min_chars
        || char_count > max_chars
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::new(field));
    }
    Ok(())
}

pub(crate) fn validate_timestamp(value: &str) -> Result<(), ValidationError> {
    parse_timestamp(value).map(|_| ())
}

pub(crate) fn parse_timestamp(value: &str) -> Result<OffsetDateTime, ValidationError> {
    if value.is_empty()
        || value.len() > 40
        || !value.is_ascii()
        || value.chars().any(|character| {
            !(character.is_ascii_digit() || matches!(character, '-' | ':' | '.' | '+' | 'T' | 'Z'))
        })
    {
        return Err(ValidationError::new(SafeFieldV1::Timestamp));
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ValidationError::new(SafeFieldV1::Timestamp))
}

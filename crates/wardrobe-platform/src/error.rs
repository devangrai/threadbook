use std::error::Error;
use std::fmt;
use std::io;

pub type PlatformResult<T> = Result<T, PlatformError>;

#[derive(Debug)]
pub enum PlatformError {
    Conflict(&'static str),
    Corrupt(&'static str),
    InvalidInput(&'static str),
    Io(io::Error),
    Json(serde_json::Error),
    Keychain(&'static str),
    LeaseLost,
    Sqlite(rusqlite::Error),
    Unsupported(&'static str),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(code) => write!(formatter, "platform conflict: {code}"),
            Self::Corrupt(code) => write!(formatter, "platform integrity failure: {code}"),
            Self::InvalidInput(field) => write!(formatter, "invalid platform input: {field}"),
            Self::Io(_) => formatter.write_str("platform filesystem operation failed"),
            Self::Json(_) => formatter.write_str("platform serialization failed"),
            Self::Keychain(code) => write!(formatter, "keychain operation failed: {code}"),
            Self::LeaseLost => formatter.write_str("job lease lost"),
            Self::Sqlite(_) => formatter.write_str("platform database operation failed"),
            Self::Unsupported(code) => write!(formatter, "platform unsupported: {code}"),
        }
    }
}

impl Error for PlatformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PlatformError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PlatformError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<rusqlite::Error> for PlatformError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

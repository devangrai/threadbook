use crate::{PlatformError, PlatformResult};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use wardrobe_core::{
    DiagnosticEventV1, DiagnosticPort, DiagnosticsEventCountV1, DiagnosticsHealthStateV1,
    DiagnosticsLogSummaryV1, PortError, PortErrorKind, PortResult, Validate, MAX_SAFE_INTEGER_V1,
};

const MAX_LINE_BYTES: usize = 4 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct JsonlDiagnostics {
    path: PathBuf,
    dropped: AtomicU64,
    access: Mutex<()>,
}

impl JsonlDiagnostics {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            dropped: AtomicU64::new(0),
            access: Mutex::new(()),
        }
    }

    pub fn append(&self, event: &DiagnosticEventV1) -> PlatformResult<bool> {
        event
            .validate()
            .map_err(|_| PlatformError::InvalidInput("diagnostic_event"))?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES {
            return Err(PlatformError::InvalidInput("diagnostic_event_too_large"));
        }

        let _access = self.lock()?;
        let mut output = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        let metadata = output.metadata()?;
        validate_log_metadata(&metadata)?;
        if metadata.len().saturating_add(line.len() as u64) > MAX_FILE_BYTES {
            self.increment_dropped();
            return Ok(false);
        }
        if unsafe { libc::fchmod(output.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        output.write_all(&line)?;
        output.sync_data()?;
        Ok(true)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn snapshot(&self) -> PlatformResult<DiagnosticsLogSummaryV1> {
        let _access = self.lock()?;
        let dropped_since_process_start = self.dropped();
        if dropped_since_process_start >= MAX_SAFE_INTEGER_V1 {
            return Err(PlatformError::Corrupt("diagnostic_drop_count"));
        }
        let (bytes, existed) = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(mut input) => (read_snapshot_prefix(&mut input)?, true),
            Err(error) if error.kind() == ErrorKind::NotFound => (Vec::new(), false),
            Err(error) => return Err(error.into()),
        };
        aggregate_snapshot(bytes, existed, dropped_since_process_start)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> PlatformResult<MutexGuard<'_, ()>> {
        self.access
            .lock()
            .map_err(|_| PlatformError::Conflict("diagnostics_log_gate"))
    }

    fn increment_dropped(&self) {
        let _ = self
            .dropped
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
    }
}

fn validate_log_metadata(metadata: &std::fs::Metadata) -> PlatformResult<()> {
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err(PlatformError::Corrupt("diagnostics_log_identity"));
    }
    Ok(())
}

fn read_snapshot_prefix(input: &mut File) -> PlatformResult<Vec<u8>> {
    let metadata = input.metadata()?;
    validate_log_metadata(&metadata)?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| PlatformError::Corrupt("diagnostics_log_length"))?;
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn aggregate_snapshot(
    mut bytes: Vec<u8>,
    existed: bool,
    dropped_since_process_start: u64,
) -> PlatformResult<DiagnosticsLogSummaryV1> {
    let truncated_line_count = u64::from(!bytes.is_empty() && !bytes.ends_with(b"\n"));
    if truncated_line_count == 1 {
        let complete_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        bytes.truncate(complete_length);
    }

    let mut malformed_line_count = 0_u64;
    let mut events = BTreeMap::new();
    let complete = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if !complete.is_empty() {
        for line in complete.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                malformed_line_count = increment_count(malformed_line_count)?;
                continue;
            }
            if line.len().saturating_add(1) > MAX_LINE_BYTES {
                malformed_line_count = increment_count(malformed_line_count)?;
                continue;
            }
            let event = match serde_json::from_slice::<DiagnosticEventV1>(line) {
                Ok(event) if event.validate().is_ok() => event,
                _ => {
                    malformed_line_count = increment_count(malformed_line_count)?;
                    continue;
                }
            };
            let count = events
                .entry((
                    event.severity,
                    event.component,
                    event.event_code,
                    event.outcome,
                ))
                .or_insert(0_u64);
            *count = increment_count(*count)?;
        }
    }
    let status = if dropped_since_process_start > 0
        || malformed_line_count > 0
        || truncated_line_count > 0
    {
        DiagnosticsHealthStateV1::NeedsAttention
    } else if existed {
        DiagnosticsHealthStateV1::Ready
    } else {
        DiagnosticsHealthStateV1::NeverRun
    };
    let mut event_counts = events
        .into_iter()
        .map(
            |((severity, component, event_code, outcome), count)| DiagnosticsEventCountV1 {
                severity,
                component,
                event_code,
                outcome,
                count,
            },
        )
        .collect::<Vec<_>>();
    event_counts.sort_by_key(|event| {
        format!(
            "{:?}:{:?}:{:?}:{:?}",
            event.severity, event.component, event.event_code, event.outcome
        )
    });
    Ok(DiagnosticsLogSummaryV1 {
        status,
        event_counts,
        dropped_since_process_start,
        malformed_line_count,
        truncated_line_count,
    })
}

fn increment_count(value: u64) -> PlatformResult<u64> {
    let incremented = value
        .checked_add(1)
        .ok_or(PlatformError::Corrupt("diagnostic_event_count"))?;
    if incremented >= MAX_SAFE_INTEGER_V1 {
        return Err(PlatformError::Corrupt("diagnostic_event_count"));
    }
    Ok(incremented)
}

impl DiagnosticPort for JsonlDiagnostics {
    fn emit(&self, event: &DiagnosticEventV1) -> PortResult<()> {
        self.append(event).map(|_| ()).map_err(|error| match error {
            PlatformError::InvalidInput(_) => PortError::new(PortErrorKind::Conflict),
            PlatformError::Io(io_error)
                if io_error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                PortError::new(PortErrorKind::PermissionDenied)
            }
            PlatformError::Io(_) => PortError::new(PortErrorKind::Unavailable),
            _ => PortError::new(PortErrorKind::Internal),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardrobe_core::{
        DiagnosticComponentV1, DiagnosticEventCodeV1, DiagnosticOutcomeV1, DiagnosticSeverityV1,
    };

    fn event() -> DiagnosticEventV1 {
        DiagnosticEventV1 {
            schema_version: 1,
            timestamp: "2026-07-15T01:05:11Z".to_owned(),
            severity: DiagnosticSeverityV1::Info,
            component: DiagnosticComponentV1::Database,
            event_code: DiagnosticEventCodeV1::CommandCompleted,
            outcome: DiagnosticOutcomeV1::Succeeded,
            operation_id: None,
        }
    }

    #[test]
    fn writes_only_bounded_allowlisted_json() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        let diagnostics = JsonlDiagnostics::new(&path);
        assert!(diagnostics.append(&event()).unwrap());
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("\"event_code\":\"command_completed\""));
        assert!(!text.contains("message"));
    }

    #[test]
    fn snapshot_counts_valid_malformed_and_truncated_lines_without_copying_them() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        let diagnostics = JsonlDiagnostics::new(&path);
        diagnostics.append(&event()).unwrap();
        {
            let _guard = diagnostics.lock().unwrap();
            let mut output = OpenOptions::new().append(true).open(&path).unwrap();
            output
                .write_all(b"private malformed sentinel\ntruncated")
                .unwrap();
            output.sync_all().unwrap();
        }
        let snapshot = diagnostics.snapshot().unwrap();
        assert_eq!(snapshot.event_counts.len(), 1);
        assert_eq!(snapshot.event_counts[0].count, 1);
        assert_eq!(
            snapshot.event_counts[0].severity,
            DiagnosticSeverityV1::Info
        );
        assert_eq!(snapshot.malformed_line_count, 1);
        assert_eq!(snapshot.truncated_line_count, 1);
        assert_eq!(snapshot.status, DiagnosticsHealthStateV1::NeedsAttention);
        assert!(!serde_json::to_string(&snapshot)
            .unwrap()
            .contains("private malformed sentinel"));
    }
}

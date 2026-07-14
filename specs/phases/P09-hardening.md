# P09: Production Hardening

Status: Baseline v0.1

### P09-UPG-001: Sign application updates
- Type: Event-driven
- Statement: When the application installs an update, the system shall verify the update signature and compatibility before changing application or data files.
- Verification: Signed-update and tampered-update tests.

### P09-BKP-001: Create recoverable backups
- Type: Event-driven
- Statement: When a scheduled or pre-upgrade backup runs, the system shall use a consistent SQLite backup and shall record the asset-manifest version required for restoration.
- Verification: Backup consistency and restore drill.

### P09-RST-001: Restore a usable catalog
- Type: Event-driven
- Statement: When the user restores a supported backup, the system shall recover confirmed decisions, source provenance, active assets, and resumable jobs without duplicating state.
- Verification: End-to-end disaster-recovery test.

### P09-DEL-001: Complete active-data deletion
- Type: Event-driven
- Statement: When a confirmed deletion plan executes, the system shall complete active local deletion within one hour and shall report backup and remote-retention expiry separately.
- Verification: Timed deletion and residual-data scan.

### P09-SUP-001: Pin distributed dependencies
- Type: Ubiquitous
- Statement: The release shall pin application dependencies and model artifacts, verify model hashes, inventory licenses, and prohibit unapproved remote model code.
- Verification: Release-manifest and supply-chain scan.

### P09-DIA-001: Export redacted diagnostics
- Type: Event-driven
- Statement: When the user exports diagnostics, the system shall include versions, health, job failures, and counters without source content, credentials, personal filenames, or model payloads.
- Verification: Diagnostic-export sensitive-data scan.

### P09-OFF-001: Support local-only operation
- Type: State-driven
- Statement: While remote inference and connectors are disabled, the production release shall support manual imports, confirmed catalog management, review, manual outfits, and deterministic collages.
- Verification: Signed packaged-app offline acceptance test.

### P09-ACC-001: Pass the production acceptance suite
- Type: Ubiquitous
- Statement: The production release shall pass migration, rollback, restore, deletion, offline, accessibility, performance, security, and packaged end-to-end acceptance suites.
- Verification: Signed release evidence bundle.

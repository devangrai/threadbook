# P01: Platform Foundation

Status: Baseline v0.1

### P01-ARC-001: Expose typed application commands
- Type: Event-driven
- Statement: When the user interface invokes an application capability, the platform shall validate a versioned typed command before executing domain logic.
- Verification: Generated-binding contract test with invalid payload cases.

### P01-DAT-001: Commit blobs atomically
- Type: Event-driven
- Statement: When source or derived bytes are stored, the platform shall verify their content hash and atomically promote them from temporary storage.
- Verification: Integration tests for normal, duplicate, and interrupted writes.

### P01-DBS-001: Maintain transactional schemas
- Type: Event-driven
- Statement: When the application opens a database with an older supported schema, the platform shall back it up and apply checksummed transactional migrations.
- Verification: Migration matrix across all retained schema fixtures.

### P01-JOB-001: Execute durable jobs
- Type: Event-driven
- Statement: When an application command enqueues background work, the platform shall persist the job, its normalized input hash, pipeline version, dependencies, and retry policy in the same transaction as the triggering state.
- Verification: Persistence integration test with forced application restart.

### P01-JOB-002: Surface terminal failures
- Type: Unwanted
- Statement: If a job exhausts its retry policy or receives a permanent error, the platform shall retain an actionable terminal failure visible to the user.
- Verification: Failure-injection integration and user-interface tests.

### P01-SEC-001: Isolate secrets
- Type: Event-driven
- Statement: When a connector or provider stores a durable credential, the platform shall place the credential in Keychain and persist only its non-secret reference.
- Verification: Keychain integration and database secret-scan tests.

### P01-OBS-001: Produce redacted diagnostics
- Type: Ubiquitous
- Statement: The platform shall emit bounded structured diagnostics without personal content, credentials, source URLs, image bytes, or model payloads.
- Verification: Log-schema test and sensitive-fixture scan.

### P01-OFF-001: Start without network access
- Type: State-driven
- Statement: While the Mac has no network connection, the platform shall start and expose local settings, job status, and empty catalog workflows.
- Verification: Packaged smoke test with networking disabled.

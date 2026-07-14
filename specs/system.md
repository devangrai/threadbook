# System Requirements

Status: Baseline v0.1

### SYS-ARC-001: Keep the domain independent
- Type: Ubiquitous
- Statement: The system shall keep domain rules independent from user-interface, persistence, connector, and model-provider implementations.
- Verification: Dependency-boundary test and architecture review.

### SYS-DAT-001: Preserve immutable source assets
- Type: Event-driven
- Statement: When the system materializes source bytes, the system shall store the bytes as an immutable content-addressed blob with provenance.
- Verification: Integration test covering duplicate and interrupted imports.

### SYS-DAT-002: Separate evidence from canonical truth
- Type: Ubiquitous
- Statement: The system shall represent observations, model outputs, similarity scores, and receipts as evidence rather than canonical wardrobe truth.
- Verification: Domain-unit tests and schema inspection.

### SYS-DEC-001: Preserve user authority
- Type: Event-driven
- Statement: When a user confirms or corrects a wardrobe decision, the system shall preserve that decision across later automated processing runs.
- Verification: Domain-unit test replaying a conflicting model run.

### SYS-REL-001: Make processing resumable
- Type: Unwanted
- Statement: If a processing job is interrupted or delivered more than once, the system shall resume or repeat it without duplicating canonical state.
- Verification: Crash-injection and duplicate-delivery integration tests.

### SYS-REL-002: Preserve offline catalog access
- Type: State-driven
- Statement: While remote providers are unavailable, the system shall keep confirmed wardrobe browsing, editing, review, and deterministic collages available.
- Verification: Packaged end-to-end test with network access disabled.

### SYS-SEC-001: Treat imports as untrusted
- Type: Event-driven
- Statement: When the system receives email, HTML, images, URLs, metadata, or model output, the system shall validate and constrain the input before using it.
- Verification: Malicious-input security corpus.

### SYS-SEC-002: Protect durable secrets
- Type: Ubiquitous
- Statement: The system shall store durable credentials in macOS Keychain and shall exclude them from databases, logs, exports, and crash reports.
- Verification: Secret-scanning integration test and manual Keychain inspection.

### SYS-PRV-001: Minimize remote disclosure
- Type: Event-driven
- Statement: When the system sends personal data to a remote provider, the system shall disclose the purpose and provider and shall send only the minimum approved derived data.
- Verification: Outbound-gateway contract tests and user-interface test.

### SYS-OBS-001: Record reproducible processing metadata
- Type: Event-driven
- Statement: When a provider or pipeline creates derived evidence, the system shall record input hashes, provider revision, prompt or model version, parameters, and parent artifacts.
- Verification: Provider contract test and evidence-schema inspection.

### SYS-DEL-001: Perform dependency-aware deletion
- Type: Event-driven
- Statement: When the user confirms hard deletion, the system shall remove reachable active originals, derivatives, embeddings, caches, and remote objects according to the displayed deletion plan.
- Verification: End-to-end deletion and residual-data scan.

### SYS-UPG-001: Protect data during upgrades
- Type: Event-driven
- Statement: When an application upgrade changes persistent schemas, the system shall create a verified backup before applying a transactional migration.
- Verification: Upgrade, rollback, and restore integration tests.

### SYS-A11Y-001: Support accessible core workflows
- Type: Ubiquitous
- Statement: The system shall provide keyboard-operable and screen-reader-compatible import, review, wardrobe, and outfit workflows.
- Verification: Automated accessibility checks and manual keyboard review.

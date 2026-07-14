# P00: Feasibility Spikes

Status: Baseline v0.1

This phase proves high-risk platform assumptions before production code depends
on them. Spike code may be discarded; measurements and decisions are retained.

### P00-PHO-001: Materialize selected PhotoKit assets
- Type: Event-driven
- Statement: When the user selects local and iCloud-backed PhotoKit assets, the feasibility build shall materialize readable local copies with stable provenance and progress reporting.
- Verification: Spike test using at least one local and one iCloud-only asset.

### P00-PKG-001: Package the desktop shell
- Type: Event-driven
- Statement: When the feasibility desktop application is archived, the build process shall produce a signed and notarizable macOS artifact without a bundled Python or PyTorch runtime.
- Verification: Clean-machine installation and signature inspection.

### P00-PKG-002: Package the local development shell
- Type: Event-driven
- Statement: When Developer ID credentials are unavailable, the feasibility build shall produce an arm64 ad-hoc signed macOS application with minimal capabilities, restrictive content security policy, denied remote navigation, and no bundled Python or PyTorch runtime.
- Verification: Local bundle, dependency, capability, navigation, architecture, and signature inspection.

### P00-JOB-001: Recover interrupted jobs
- Type: Unwanted
- Statement: If the feasibility job runner terminates during a leased job, the restarted runner shall recover the job without duplicating committed output.
- Verification: Process-termination integration test.

### P00-SEG-001: Benchmark segmentation candidates
- Type: Event-driven
- Statement: When candidate Mac segmentation providers process the labeled feasibility dataset, the evaluation shall record recall, mask quality, latency, memory, package size, and failure rate by provider revision.
- Verification: Reproducible private evaluation report.

### P00-GML-001: Prove Gmail synchronization recovery
- Type: Unwanted
- Statement: If a Gmail history cursor is expired or invalid, the feasibility connector shall fall back to a bounded full reconciliation without creating duplicate source records.
- Verification: Connector spike with simulated cursor expiration.

### P00-AI-001: Prove structured multimodal responses
- Type: Event-driven
- Statement: When the feasibility client submits sanitized receipt text or approved image crops, the OpenAI provider shall return schema-valid output or an explicit refusal without mutating catalog state.
- Verification: Contract tests covering success, refusal, timeout, and malformed output.

### P00-PRV-001: Record remote-data boundaries
- Type: Event-driven
- Statement: When a feasibility spike uses a remote provider, the evaluation shall record the transmitted fields, retention configuration, provider request identifier, latency, and estimated cost.
- Verification: Outbound-request audit from the spike dataset.

### P00-GAT-001: Gate architecture decisions
- Type: Ubiquitous
- Statement: The feasibility phase shall document an accepted fallback for every failed spike before dependent production work begins.
- Verification: Architecture-decision review against the phase report.

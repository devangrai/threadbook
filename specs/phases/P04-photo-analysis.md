# P04: Photo Analysis

Status: Baseline v0.1

### P04-SCP-001: Require an explicit photo scope
- Type: Event-driven
- Statement: When photo analysis begins, the system shall process only assets in a user-selected PhotoKit scope or imported folder snapshot.
- Verification: Scope-boundary integration test.

### P04-PER-001: Detect person instances locally
- Type: Event-driven
- Statement: When a scoped photo contains visible people, the system shall create locally detected person instances without assigning an identity from Apple Photos metadata.
- Verification: Apple Vision fixture and native integration tests.

### P04-OWN-001: Confirm ambiguous owner presence
- Type: Unwanted
- Statement: If a photo contains multiple person instances or uncertain owner presence, the system shall require user confirmation before associating garment observations with the owner.
- Verification: Multi-person review workflow test.

### P04-SEG-001: Keep segmentation replaceable
- Type: Event-driven
- Statement: When garment segmentation is requested, the system shall use a versioned provider contract that supports automatic masks, interactive prompts, and an unavailable result.
- Verification: Provider conformance tests.

### P04-SEG-002: Degrade without a mask
- Type: Unwanted
- Statement: If garment segmentation fails its quality gate, the system shall retain a rectangular crop or source image and mark the observation for review instead of discarding it.
- Verification: Forced-failure integration test.

### P04-ART-001: Version visual artifacts
- Type: Event-driven
- Statement: When photo analysis creates a mask, crop, descriptor, or embedding, the system shall record its parent assets and exact preprocessing and provider revisions.
- Verification: Artifact-provenance integration test.

### P04-QLT-001: Meet automatic mask quality
- Type: Optional
- Statement: Where automatic garment segmentation is enabled, the provider shall achieve at least eighty-five percent recall at intersection-over-union point five and mean mask intersection-over-union of at least point six five on the approved Mac dataset.
- Verification: Private segmentation evaluation report.

### P04-PERF-001: Respect Mac resource budgets
- Type: Optional
- Statement: Where a local segmentation model pack is enabled, the provider shall keep warm p95 processing below three seconds per person and peak application memory below two point five gigabytes on the baseline Mac.
- Verification: Repeatable performance benchmark.

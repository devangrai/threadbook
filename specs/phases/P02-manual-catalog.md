# P02: Manual Catalog And Imports

Status: Baseline v0.1

### P02-IMP-001: Import local photo folders
- Type: Event-driven
- Statement: When the user imports a photo folder, the system shall reconcile a completed manifest scan into source records without treating an unavailable folder as deleted content.
- Verification: Folder integration tests covering rename, duplicate, and unavailable-volume cases.

### P02-IMP-002: Import standard email files
- Type: Event-driven
- Statement: When the user imports EML or supported MBOX content, the system shall preserve the raw message bytes, source identity, MIME relationships, and parsing diagnostics.
- Verification: Fixture tests across MIME and MBOX variants.

### P02-IMP-003: Deduplicate bytes without merging sources
- Type: Event-driven
- Statement: When multiple source records contain identical bytes, the system shall reuse the immutable blob while preserving each logical source record and provenance chain.
- Verification: Duplicate-source integration test.

### P02-CAT-001: Manage wardrobe items manually
- Type: Event-driven
- Statement: When the user creates or edits a wardrobe item, the system shall save validated resolved attributes with an append-only decision record.
- Verification: Domain and user-interface tests.

### P02-CAT-002: Reverse merge and split operations
- Type: Event-driven
- Statement: When the user merges or splits wardrobe evidence, the system shall retain enough decision history to reverse the operation without losing source evidence.
- Verification: Round-trip merge, split, and undo tests.

### P02-REV-001: Present an evidence inbox
- Type: Event-driven
- Statement: When unresolved imported evidence exists, the system shall present it separately from the confirmed wardrobe and shall allow assignment, rejection, or deferral.
- Verification: Playwright review-workflow test.

### P02-SAF-001: Quarantine unsafe imports
- Type: Unwanted
- Statement: If imported MIME or image content violates type, size, pixel, frame, or decoding limits, the system shall quarantine the source record and continue processing other records.
- Verification: Malicious-file and decompression-bomb corpus.

### P02-DEL-001: Preview deletion effects
- Type: Event-driven
- Statement: When the user requests hard deletion, the system shall display the originals, derivatives, records, and remote references included in the deletion plan before execution.
- Verification: Deletion-plan integration and interface tests.

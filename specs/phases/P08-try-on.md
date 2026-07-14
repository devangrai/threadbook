# P08: Try-On Visualization

Status: Baseline v0.1

### P08-EXP-001: Require explicit generation
- Type: Event-driven
- Statement: When the user explicitly requests visualization for a saved outfit, the system shall create an asynchronous generation job using the selected portrait and garment references.
- Verification: User-interface and job integration tests.

### P08-LBL-001: Label generated output
- Type: Ubiquitous
- Statement: The system shall label generated try-on output as an AI visualization rather than an accurate representation of fit or garment construction.
- Verification: Accessibility and interface-content test.

### P08-SRC-001: Display source garments
- Type: Event-driven
- Statement: When a generated try-on is displayed, the system shall display the real source garment assets and outfit identifiers alongside it.
- Verification: Playwright visualization-detail test.

### P08-EVD-001: Exclude generated evidence
- Type: Ubiquitous
- Statement: The system shall exclude generated try-on images from garment matching, owner identification, wear history, and catalog evidence.
- Verification: Domain-boundary and data-flow tests.

### P08-ERR-001: Preserve outfits after generation failure
- Type: Unwanted
- Statement: If generation fails, times out, is rate-limited, or is blocked, the system shall preserve the outfit and its deterministic collage and shall expose an actionable job result.
- Verification: Provider-failure integration tests.

### P08-PRV-001: Confirm portrait disclosure
- Type: Event-driven
- Statement: When a remote try-on request includes a personal portrait, the system shall display the provider and transmitted assets before submission.
- Verification: Consent-dialog and outbound-gateway tests.

### P08-QLT-001: Gate production availability
- Type: Optional
- Statement: Where try-on is available outside an experimental feature flag, the renderer shall pass the approved human evaluation thresholds for identity, garment detail, and misleading-output rate.
- Verification: Blinded human evaluation report.

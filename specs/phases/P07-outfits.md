# P07: Outfit Assistant

Status: Baseline v0.1

### P07-TOL-001: Expose read-only wardrobe tools
- Type: Ubiquitous
- Statement: The outfit reasoning provider shall receive only read-only tools for searching confirmed wardrobe items, wear history, preferences, and saved outfits.
- Verification: Tool-registry contract test.

### P07-AI-001: Return structured outfit proposals
- Type: Event-driven
- Statement: When the user requests outfit ideas, the reasoning provider shall return a versioned structured proposal containing known wardrobe identifiers, rationale, caveats, and unresolved constraints.
- Verification: Structured-output contract and refusal tests.

### P07-VAL-001: Validate model-selected items
- Type: Event-driven
- Statement: When an outfit proposal is received, the system shall reject unknown, unavailable, duplicate, incompatible, or stale wardrobe identifiers before presenting the proposal.
- Verification: Adversarial proposal validation tests.

### P07-GRD-001: Prevent invented garments
- Type: Ubiquitous
- Statement: The outfit pipeline shall produce zero accepted invented wardrobe identifiers across the approved grounding evaluation set.
- Verification: Evaluation of at least five hundred representative prompts.

### P07-CNS-001: Satisfy explicit constraints
- Type: Ubiquitous
- Statement: The outfit pipeline shall satisfy at least ninety-eight percent of supported occasion, weather, availability, and exclusion constraints in the approved evaluation set.
- Verification: Deterministic constraint evaluation.

### P07-COL-001: Render deterministic collages
- Type: Event-driven
- Statement: When the user requests an outfit collage, the system shall compose it from real catalog assets without generated garment reconstruction.
- Verification: Visual-regression and asset-provenance tests.

### P07-OFF-001: Preserve deterministic outfit access
- Type: State-driven
- Statement: While the reasoning provider is unavailable, the system shall allow browsing saved outfits and creating manual outfits and collages.
- Verification: Offline Playwright workflow.

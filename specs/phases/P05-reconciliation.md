# P05: Receipt And Photo Reconciliation

Status: Baseline v0.1

### P05-CAN-001: Preserve a no-match candidate
- Type: Event-driven
- Statement: When purchase or wardrobe candidates are retrieved for an observation, the system shall include an explicit no-match outcome.
- Verification: Candidate-retrieval unit and integration tests.

### P05-IDN-001: Distinguish identity relations
- Type: Ubiquitous
- Statement: The system shall represent visual similarity, same product variant, and same physical wardrobe item as distinct relations.
- Verification: Domain-schema and state-transition tests.

### P05-EVD-001: Preserve supporting and contradictory evidence
- Type: Event-driven
- Statement: When a candidate is scored, the system shall retain supporting, contradictory, and neutral evidence with source and extractor versions.
- Verification: Candidate-evidence contract test.

### P05-AI-001: Limit model adjudication authority
- Type: Event-driven
- Statement: When a model compares a photo observation and product evidence, the system shall use its structured verdict as one evidence feature and shall not treat model confidence as a calibrated probability.
- Verification: Provider and decision-policy tests.

### P05-REV-001: Show alternatives during review
- Type: Event-driven
- Statement: When the user reviews a proposed match, the system shall show the leading candidate, relevant alternatives, dates, and supporting and contradictory evidence.
- Verification: Playwright review-case test.

### P05-DEC-001: Support explicit uncertainty
- Type: Event-driven
- Statement: When the user decides a review case, the system shall support same item, same variant, different, no match, and unresolved outcomes.
- Verification: Domain and interface tests for every decision.

### P05-AUT-001: Gate automatic acceptance
- Type: Optional
- Statement: Where automatic match acceptance is enabled, the calibrated policy shall demonstrate at least ninety-nine percent precision on held-out hard negatives with no hard contradiction.
- Verification: Versioned calibration and precision-coverage report.

### P05-QLT-001: Retrieve useful alternatives
- Type: Ubiquitous
- Statement: The reconciliation pipeline shall achieve at least ninety-five percent top-three recall on the approved candidate-retrieval evaluation set.
- Verification: Garment-disjoint retrieval evaluation.

# P03: Receipt Intelligence

Status: Baseline v0.1

### P03-MIM-001: Parse message structure before inference
- Type: Event-driven
- Statement: When an imported message is analyzed as a potential receipt, the system shall parse MIME structure, text, attachments, content identifiers, and sanitized HTML before invoking a model.
- Verification: Receipt-parser fixture suite.

### P03-ORD-001: Separate orders from product variants
- Type: Event-driven
- Statement: When receipt evidence describes a purchased line item, the system shall represent the order item separately from its inferred product variant and any physical wardrobe item.
- Verification: Domain tests for quantity, exchange, return, and unknown-product cases.

### P03-AI-001: Extract receipts with a strict schema
- Type: Event-driven
- Statement: When the receipt provider analyzes sanitized message evidence, the system shall require a versioned Structured Output containing explicit unknown values and source references.
- Verification: Provider contract and schema-conformance tests.

### P03-AI-002: Avoid fabricated identifiers
- Type: Unwanted
- Statement: If receipt evidence does not establish a brand, SKU, size, color, price, or order identifier, the system shall record the field as unknown rather than infer a specific value.
- Verification: Labeled hard-negative evaluation set.

### P03-SAF-001: Ignore instructions in imported content
- Type: Unwanted
- Statement: If receipt text or images contain instructions directed at the model or application, the system shall treat them as quoted evidence and shall not grant tools or side effects to the extraction request.
- Verification: Prompt-injection fixture suite.

### P03-IMG-001: Retrieve product images safely
- Type: Event-driven
- Statement: When the system retrieves a remote receipt image, the downloader shall enforce protocol, redirect, address, MIME, byte, pixel, and timeout policies without sending ambient credentials.
- Verification: SSRF and tracking-image integration tests.

### P03-QLT-001: Meet receipt extraction quality
- Type: Ubiquitous
- Statement: The receipt pipeline shall achieve at least ninety-five percent item recall on the approved labeled receipt set while reporting unsupported fields as unknown.
- Verification: Versioned receipt evaluation report.

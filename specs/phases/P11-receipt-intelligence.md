# P11: OpenAI Receipt Intelligence

Status: Baseline v0.1

### P11-CLS-001: Classify apparel commerce messages
- Type: Event-driven
- Statement: When remote receipt intelligence analyzes approved message evidence, the system shall classify the message as an apparel order, apparel lifecycle update, unrelated message, or ambiguous message before publishing extracted order evidence.
- Verification: Labeled apparel, footwear, accessory, food, travel, service, shipping, cancellation, return, exchange, and ambiguous-message fixture suite.

### P11-CLS-002: Keep unrelated messages out of order evidence
- Type: Unwanted
- Statement: If remote receipt intelligence classifies a message as unrelated or ambiguous, the system shall publish no receipt order graph or wardrobe item and shall preserve the classification as reviewable evidence.
- Verification: Repository integration tests for unrelated and ambiguous terminal outcomes.

### P11-PRV-001: Preview minimum remote disclosure
- Type: Event-driven
- Statement: When remote receipt intelligence is previewed, the system shall disclose the provider, model, purpose, exact visible-text fragments, byte count, local retention, provider-retention provenance, and the fact that `store:false` is not organization-level Zero Data Retention, and shall exclude raw MIME, headers, URLs, filenames, attachment and CID metadata, internal identifiers, hashes, credentials, and image bytes from the remote payload.
- Verification: Preview contract, UI disclosure, outbound allowlist, and forbidden-sentinel tests.

### P11-AUT-001: Bind approval to the exact disclosure
- Type: Event-driven
- Statement: When the user approves remote receipt intelligence, the system shall issue an expiring single-use approval bound to the source revision, disclosed-fragment hashes, provider, model, credential reference, retention declaration, prompt revision, schema revision, and all configured bounds.
- Verification: Approval expiry, replay, changed-envelope, credential-change, and cancellation tests.

### P11-SEC-001: Retrieve only the selected provider credential
- Type: Event-driven
- Statement: When an approved remote receipt request is dispatched, the system shall retrieve only the selected active OpenAI credential from macOS Keychain immediately before transport and shall exclude every credential from databases, logs, diagnostics, exports, errors, and provider payload content.
- Verification: Keychain integration, credential-race, diagnostics export, and secret-sentinel tests.

### P11-BND-001: Enforce closed preparation bounds
- Type: Event-driven
- Statement: When remote receipt intelligence is prepared, the system shall enforce configured fragment-count, fragment-byte, aggregate-text-byte, and serialized-request-byte limits before approval and shall fail rather than silently truncate evidence.
- Verification: Exact-boundary and one-over projection and approval tests.

### P11-BND-002: Enforce closed execution bounds
- Type: Event-driven
- Statement: When remote receipt intelligence is executed, the system shall enforce configured request-byte, response-byte, output-token, timeout, and attempt limits before the relevant side effect and shall fail rather than silently truncate evidence or retry.
- Verification: Exact-boundary and one-over provider and coordinator tests.

### P11-AI-001: Use a stateless strict Responses request
- Type: Event-driven
- Statement: When the OpenAI receipt provider dispatches approved evidence, the provider shall use `gpt-5.6-sol` through the Responses API with `store:false`, background processing disabled, no tools, no previous response, a strict versioned JSON Schema in `text.format`, and an explicit bounded reasoning effort.
- Verification: Concrete TLS transport request snapshot and schema contract tests.

### P11-AI-002: Preserve explicit unknowns and provenance
- Type: Event-driven
- Statement: When the provider returns receipt intelligence, the system shall require explicit unknown values, bounded apparel line items, event kinds, quantities, prices, product attributes, exact source quotes, and provider, model, prompt, schema, projection, parameter, parent-source, and usage provenance.
- Verification: Strict decoding, unknown-field, model-provenance, and output-bound tests.

### P11-SAF-001: Treat message instructions as evidence
- Type: Unwanted
- Statement: If approved message text contains instructions, role markers, delimiters, links, or requests for tools or side effects, the system shall encode it as untrusted structured data, grant no tools or callbacks, and accept only the strict receipt-intelligence output schema.
- Verification: Prompt-injection and cross-fragment adversarial fixture suite.

### P11-CIT-001: Validate every known value against exact source bytes
- Type: Event-driven
- Statement: When a provider reports a known receipt value, the system shall resolve each supporting quote to one unique UTF-8 byte span in the approved fragment, verify its hash against the immutable local fragment, and require the value to equal or follow an allowlisted deterministic normalization of the quoted bytes before publishing it.
- Verification: Exact quote, duplicate quote, missing quote, Unicode boundary, unrelated quote, altered value, and normalized numeric-field tests.

### P11-REL-001: Reserve consent atomically
- Type: Event-driven
- Statement: When the user affirmatively approves the exact remote receipt disclosure, the system shall atomically create and consume one expiring single-use approval and reserve one idempotent not-sent attempt before credential access or transport; exact command replay shall return the same reservation and changed command replay shall conflict.
- Verification: Consent cancellation, exact replay, changed-envelope, expiry, crash-injection, database-reopen, and zero-credential and zero-transport tests.

### P11-REL-002: Track dispatch without automatic retry
- Type: Event-driven
- Statement: When a reserved remote receipt attempt executes, the system shall distinguish not-sent, dispatched, completed, refused, failed, and outcome-unknown states and shall prohibit automatic retry after dispatch or an outcome-unknown result.
- Verification: Timeout, transport ambiguity, crash injection, restart recovery, and no-automatic-retry tests.

### P11-ATM-001: Publish validated evidence atomically
- Type: Unwanted
- Statement: If provider transport, response parsing, classification, citation validation, domain validation, or persistence fails, the system shall publish no partial classification, order, line, variant, review-head, or wardrobe graph and shall retain only bounded content-free attempt metadata appropriate to the dispatch state.
- Verification: Injected-failure transaction tests with residual-row and restart scans.

### P11-DEC-001: Preserve user receipt decisions
- Type: Event-driven
- Statement: When remote receipt intelligence succeeds for a source with an existing user receipt decision, the system shall append new evidence without overwriting the confirmed, corrected, deferred, or rejected user decision.
- Verification: Reanalysis integration tests across every receipt review action.

### P11-GAT-001: Fail closed when remote intelligence is unavailable
- Type: State-driven
- Statement: While local-only mode, release evidence, outbound authority, an active OpenAI credential, or a current retention declaration is unavailable, the system shall keep offline receipt analysis and existing wardrobe access available, disable remote receipt intelligence truthfully, and perform no provider request.
- Verification: Packaged disabled-state, local-only, missing-credential, stale-retention, and no-network tests.

### P11-UI-001: Expose exact preview and approval
- Type: Event-driven
- Statement: When the user previews remote receipt intelligence, the interface shall present the exact disclosure and configured bounds, permit cancellation without approval or provider side effects, and bind approval to the displayed preview.
- Verification: Component accessibility tests and desktop preview-and-approval smoke.

### P11-UI-002: Expose safe execution states
- Type: Event-driven
- Statement: When an approved remote receipt request executes, the interface shall expose safe progress and terminal states including completion, unrelated, ambiguous, refusal, failure, and outcome unknown and shall require a separate user review before extracted evidence can become canonical wardrobe data.
- Verification: Component state tests and desktop execution-to-review smoke.

### P11-E2E-001: Analyze a Gmail source through review
- Type: Event-driven
- Statement: When a committed Gmail source containing an apparel order is approved for remote receipt intelligence, the system shall classify and extract its unique order lines, validate exact source evidence, persist the result atomically, and make it available in the existing receipt review workflow without creating a wardrobe item automatically.
- Verification: Gmail-source to OpenAI-protocol fixture to persisted receipt-review end-to-end smoke, plus an opt-in live canary when credentials are available.

# P10: Gmail To Wardrobe

Status: Baseline v0.1

### P10-GML-001: Configure typed discovery scopes
- Type: Event-driven
- Statement: When Gmail settings V2 are saved, the system shall accept exactly one discovery variant, either `{kind: search, query}` or `{kind: label, label_name}`, reject mixed or unknown fields, validate search queries as 1-2,048 UTF-8 bytes without control characters, trimming, or normalization, and shall not require a Gmail label in search mode.
- Verification: V2 contract, validation, and serialization tests.

### P10-GML-002: Preserve legacy label settings
- Type: Event-driven
- Statement: When existing Gmail settings V1 are loaded after the V2 migration, the system shall durably migrate them to a V2 label discovery scope while preserving the exact label name, account key, resolved label identifier, history cursor, credential reference, connection state, label reconciliation behavior, and expired-cursor recovery behavior.
- Verification: Settings migration and legacy connector regression tests.

### P10-GML-003: Identify search scopes exactly
- Type: Event-driven
- Statement: When a search scope is created, the system shall derive its versioned identity tuple from the Gmail account key, discovery kind, exact UTF-8 query bytes, exact ordered OAuth scope strings, parser revision, and materialization revision, and any tuple-field or query-byte change shall create a distinct logical scope.
- Verification: Scope fingerprint and query-change identity tests.

### P10-GML-004: Reconcile search results completely
- Type: Event-driven
- Statement: When search-mode connection or synchronization begins, the system shall execute the exact configured Gmail query with `includeSpamTrash=false`, exhaust its result pages within configured limits, deduplicate message identifiers, and retrieve every unique listed message before publishing the reconciliation; if a next-page token remains when a configured boundary is reached, the reconciliation shall fail.
- Verification: Paginated search reconciliation integration test.

### P10-GML-005: Fail bounded synchronization atomically
- Type: Unwanted
- Statement: If search reconciliation exceeds a page, message, byte, call, or time limit, or encounters a malformed response, retrieval failure, or persistence failure, the system shall leave previously committed Gmail domain state and scan watermarks unchanged, publish no new source, revision, materialization, or evidence, remove newly staged raw content, and may retain only content-free failure metadata.
- Verification: Limit-boundary and injected-failure atomicity tests.

### P10-GML-006: Deduplicate provider revisions
- Type: Event-driven
- Statement: When duplicate search results or later successful scans contain the same Gmail account key, provider message identifier, and canonical provider history identifier, the system shall publish exactly one source revision for that provider revision.
- Verification: Duplicate-page and repeated-scan tests.

### P10-GML-007: Retain imported search evidence
- Type: Event-driven
- Statement: When a previously imported message is absent from a later search result, the system shall retain its imported source and evidence and shall not mark it unavailable or delete it solely because it no longer matches the query.
- Verification: Rolling-query and search-membership regression tests.

### P10-GML-008: Recover interrupted search synchronization
- Type: Unwanted
- Statement: If the application restarts during search synchronization before atomic publication, the system shall discard the incomplete operation, preserve the previously committed scope and evidence, and permit a complete bounded retry.
- Verification: Interrupted-operation restart and database-reopen tests.

### P10-GML-009: Keep search and label synchronization distinct
- Type: Ubiquitous
- Statement: The Gmail connector shall use complete query reconciliation for search scopes and persisted Gmail history for label scopes without applying history events or known-but-unlisted reconciliation to a search scope.
- Verification: Coordinator dispatch and legacy label-history regression tests.

### P10-GML-010: Replay commands idempotently
- Type: Event-driven
- Statement: When the same request identifier and canonical command envelope are replayed, the system shall return the original terminal response without provider calls or durable writes, and reuse of that request identifier with a different canonical command envelope shall conflict.
- Verification: Exact-replay and request-identifier conflict tests.

### P10-AUT-001: Restrict Gmail authority
- Type: Ubiquitous
- Statement: The Gmail connector shall request exactly `openid` and `https://www.googleapis.com/auth/gmail.readonly`, shall use `gmail.readonly` as its sole Gmail API data scope, shall issue no Gmail mutation requests, and shall not create labels, apply labels, modify messages, send mail, or delete mailbox data in either discovery mode.
- Verification: OAuth-scope assertion and HTTP method and path allowlist tests.

### P10-UI-001: Disclose search behavior
- Type: Event-driven
- Statement: When the user configures or connects a search discovery scope, the interface shall disclose the exact query, configured bounds, read-only authority, complete-reconciliation behavior, and retention of previously imported messages.
- Verification: Settings UI component and packaged end-to-end smoke tests.

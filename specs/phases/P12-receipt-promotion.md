# P12: Receipt Purchase Unit Promotion

Status: Baseline v0.1

### P12-PRJ-001: Project only eligible purchase units
- Type: Event-driven
- Statement: When receipt purchase units are listed, the system shall project only purchase lines governed by the current confirmed or corrected user-review authority, shall expand each known positive quantity into one independently promotable physical unit, and shall report bounded reasons for review-required, rejected, deferred, non-purchase, and unknown-quantity exclusions.
- Verification: Projection tests covering every review action, event kind, unknown field, quantity boundary, correction, and superseded authority.

### P12-IDN-001: Identify physical units stably
- Type: Ubiquitous
- Statement: The system shall identify each receipt purchase unit by a versioned identity derived from its order line and zero-based unit ordinal, shall keep that identity distinct from order, variant, evidence, and catalog item identities, and shall expose snapshot-bound revisions for compare and swap.
- Verification: Domain contract, quantity expansion, identity collision, and pagination snapshot tests.

### P12-PRV-001: Preserve receipt provenance as evidence
- Type: Event-driven
- Statement: When the system projects or promotes a receipt purchase unit, the system shall preserve the effective user-reviewed values and their exact receipt citations or user-correction provenance as immutable evidence and shall not treat model output as canonical wardrobe truth.
- Verification: Evidence-schema inspection and confirmed, corrected, unknown, and reanalysis provenance tests.

### P12-AUT-001: Require explicit item authority
- Type: Event-driven
- Statement: When a user promotes a receipt purchase unit, the system shall require a separate affirmative confirmation and complete validated canonical item attributes, including a user-selected category, bound to the displayed purchase-unit, receipt-authority, and catalog revisions.
- Verification: Strict command-contract tests for confirmation, attributes, authority binding, stale drafts, and cancellation without mutation.

### P12-CAS-001: Reject stale promotion authority
- Type: Unwanted
- Statement: If the current receipt authority, purchase-unit revision, purchase eligibility, or catalog revision differs from the promotion command, the system shall reject the command without creating or changing canonical, evidence, decision, audit, revision, or replay state.
- Verification: Concurrent authority, correction, quantity, event, catalog, and duplicate-promotion compare-and-swap tests with residual-row scans.

### P12-ATM-001: Promote one unit atomically
- Type: Event-driven
- Statement: When a valid receipt purchase unit is promoted, the system shall atomically create exactly one canonical wardrobe item, one unit evidence assignment, one user-confirmed promotion decision, immutable promotion provenance and audit links, the required revision changes, and one terminal command receipt.
- Verification: Repository integration and crash-injection tests across every write boundary.

### P12-REL-001: Replay promotion before current-state checks
- Type: Event-driven
- Statement: When an exact terminal promotion command is replayed, the system shall return the original item and response before current-state checks and without writes, and reuse of its request identifier with any changed canonical command field shall conflict.
- Verification: Restart, exact-replay, changed-envelope, concurrent-request, and write-count tests.

### P12-DEC-001: Preserve promoted user decisions
- Type: Unwanted
- Statement: If later receipt analysis, review, correction, return, exchange, or source synchronization conflicts with a promoted purchase unit, the system shall preserve the canonical item and promotion decision for explicit user resolution and shall not silently rewrite, duplicate, or delete them.
- Verification: Reanalysis and lifecycle-event tests after promotion, including restart and exact replay.

### P12-DEL-001: Delete promotion dependencies completely
- Type: Event-driven
- Statement: When the user confirms deletion of a source, purchase unit, evidence record, or promoted item, the system shall include every reachable promotion, authority snapshot, decision, audit link, replay receipt, and exclusively owned blob in the deletion plan and shall preserve shared dependencies explicitly reported by that plan.
- Verification: Dependency-closure, shared-source, sibling-unit, restart, and residual-data deletion tests.

### P12-UPG-001: Migrate promotion storage safely
- Type: Event-driven
- Statement: When the application first installs storage for receipt purchase unit promotion, the system shall create a verified pre-upgrade backup before applying one transactional strict-schema migration and shall restore the prior usable schema if migration is interrupted or rejected.
- Verification: Populated-database migration, checksum tampering, interruption, rollback, backup verification, and reopen tests.

### P12-UI-001: Review and promote units accessibly
- Type: Event-driven
- Statement: When an eligible purchase unit is displayed, the interface shall show its reviewed values and provenance, preserve an editable canonical-item draft across conflicts, require an explicit one-item confirmation, expose safe success and conflict states, and support keyboard and screen-reader operation without creating duplicate items.
- Verification: Component accessibility, focus, cancellation, conflict, narrow-viewport, and success-navigation tests.

### P12-E2E-001: Add a reviewed Gmail purchase to the wardrobe
- Type: Event-driven
- Statement: When a Gmail apparel order has been analyzed and confirmed or corrected by the user, the system shall list its eligible physical purchase units, promote one explicitly confirmed unit into one canonical wardrobe item through the production local application path, and preserve the item, provenance, promoted status, and exact replay across restart.
- Verification: Persisted Gmail-source to reviewed receipt to canonical item desktop smoke with restart, replay, and zero remote calls during promotion.

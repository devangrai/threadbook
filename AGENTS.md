# Development Contract

These rules apply to the entire repository.

## Required workflow

1. Read `specs/system.md` and the applicable phase specification.
2. Run `make check`.
3. Generate a work packet with `tools/harness.py generate`.
4. Complete the generated proposal and verification plan.
5. Obtain an independent review with an explicit approval.
6. Build only the approved scope.
7. Run tests and produce requirement-level evidence.
8. Evaluate the work packet. Do not call the phase complete unless evaluation
   passes.

## Personal MVP delivery profile

- Keep work packets minimal and limited to one usable vertical slice.
- Use one independent review pass before implementation.
- Add focused unit tests and one end-to-end smoke test for each phase.
- Run the full repository regression suite at phase boundaries.
- Prefer real local adapters and provider sandboxes over certification
  infrastructure. Production paths must not depend on test mocks.
- Record credentials, notarization, clean-machine certification, and
  unavailable third-party models as explicit deferred limitations. A deferred
  external capability does not block later phases when an accepted local
  fallback preserves privacy, data integrity, deletion, and user authority.
- Keep automatic or remote behavior disabled until its own requirement has
  real evidence. Deferred capability must never be presented as passed.
- Preserve strict guarantees for credentials, remote disclosure, atomic
  writes, backups and migrations, dependency-aware deletion, idempotency, and
  user-confirmed decisions.

## Architecture boundaries

- Domain code must not depend on Tauri, SQLite, PhotoKit, OpenAI, or network
  clients.
- External systems must be accessed through explicit connector or provider
  interfaces.
- Model output is evidence, never canonical truth.
- User-confirmed decisions must not be overwritten by automated processing.
- Generated images must never be used as identity or matching evidence.
- Every job and mutation must be idempotent.

## Change discipline

- Keep requirement IDs stable. Supersede requirements instead of silently
  changing their meaning.
- Any requirement change after work-packet generation invalidates that packet.
- Add tests with implementation changes.
- Add migration, rollback, deletion, and failure-path coverage where relevant.
- Do not weaken an evaluation threshold to make a failing implementation pass
  without an approved specification change.
- Keep experimental providers behind feature flags.

## Sensitive data

- Never commit personal data or credentials.
- Never log receipt bodies, image bytes, access tokens, face data, or model
  request payloads.
- Use synthetic fixtures in automated tests.

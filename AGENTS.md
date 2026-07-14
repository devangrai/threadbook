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

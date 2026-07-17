# Wardrobe Home-Mac Handoff

This is the starting point for a new Codex or Claude Code session. Read
`AGENTS.md`, this file, and `specs/README.md` before changing code.

## Current state

Wardrobe is a local-first macOS Tauri application. React calls versioned Tauri
commands; `wardrobe-core` owns contracts and services; `wardrobe-platform`
owns SQLite, blobs, Keychain, Gmail, PhotoKit, OpenAI, backup, and deletion
adapters. User review is canonical. Provider/model output is evidence only.

- P00-P09: personal-MVP foundation and hardening implemented.
- P10: Gmail discovery/import implemented and locally accepted.
- P11: citation-bound OpenAI receipt intelligence implemented and locally accepted.
- P12: reviewed receipt purchase-unit promotion implemented. Focused core,
  repository, migration, Tauri, UI, and Playwright tests pass; final harness
  acceptance remains.
- Live Gmail, OpenAI, Apple Photos, notarization, and clean-machine checks are
  environment-dependent work for the home Mac, not completed claims.

## Fresh clone

Required: a personal Mac running macOS 15 or later, Xcode and Command Line Tools, stable Rust, Node.js 22
LTS with npm, and Python 3.

```bash
git clone https://github.com/devangrai/threadbook.git
cd threadbook
xcode-select --install  # skip if already installed
npm ci --ignore-scripts
cargo fetch --locked
make check
make test
npm run desktop:dev
```

`make build` is deliberately offline after dependency preparation. Git does
not contain the private database, blobs, logs, Keychain entries, credentials,
personal messages, photos, or ignored harness run directories.

Start every resumed agent session with:

```bash
git status --short
git log -1 --oneline
python3 tools/harness.py validate
cargo test -p wardrobe-platform --lib receipt_promotion_repository_tests:: -- --test-threads=1
```

## Finish P12 first

The original approved run ID was `20260717T012423Z-64b81c09`. Harness run
directories are intentionally ignored, so generate and independently approve a
replacement P12 packet if that run is absent on the clone.

```bash
cargo test -p wardrobe-core --test receipt_promotion_contracts -- --test-threads=1
cargo test -p wardrobe-platform --lib receipt_promotion_repository_tests:: -- --test-threads=1
cargo test -p wardrobe-desktop receipt_purchase_unit_commands_use_real_local_state_across_restart -- --test-threads=1
npm --workspace @wardrobe/desktop-ui test -- --run ReceiptPurchaseUnits.test.tsx receipt-promotion-bridge.test.ts
npm --workspace @wardrobe/desktop-ui run test:e2e -- receipt-promotion.spec.ts
python3 -m unittest tests.test_p12_receipt_promotion_evaluator
```

The evaluator requires a genuine run-scoped 390x844 keyboard review record.
Build before recording it because rebuilding clears evidence. Never synthesize
manual evidence from automated output.

## Gmail activation

Use OAuth, never an app password. Previously shared credentials must be rotated
and treated as compromised; none belong in this repository.

1. In a personal Google Cloud project, enable the Gmail API.
2. Configure the OAuth consent screen and add the Gmail account as a test user.
3. Create an OAuth client of type **Desktop app**. The implementation uses
   authorization-code PKCE and a loopback redirect; no client secret is stored.
4. Start the app and change Network mode from **Local only** to
   **Personal live**. Under **Settings > Gmail**, enter only the desktop client ID,
   choose bounded search-query discovery, and save.
5. Connect in the browser and confirm the intended personal account.
6. Sync only the last three months first. Inspect discovered messages and
   receipt counts before broadening the query.
7. Review receipts. Only confirmed/corrected purchase units can be promoted.

Review `GOOGLE_OAUTH_SCOPE` in `crates/wardrobe-platform/src/gmail_http.rs`
against current restricted-scope policy before distribution:

- https://developers.google.com/workspace/gmail/api/quickstart
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/gmail/api/auth/scopes

Live acceptance must cover cancellation, refresh after restart, bounded sync,
replay, disconnect/revocation, local-only blocking, redaction, and deletion.
Never log raw messages, tokens, secrets, or personal receipt text.

## OpenAI receipt intelligence

The Responses API adapter uses strict structured output, `store: false`,
bounded disclosed fragments, exact citations, explicit consent, and a
fail-closed release manifest. Store the API key through the app's macOS
Keychain credential flow, never `.env`, source, SQLite, or logs. Re-run P11 and
supply-chain checks after changing the model, prompt, schema, or evaluator.

- https://developers.openai.com/api/docs/guides/structured-outputs
- https://developers.openai.com/api/docs/guides/text

## Photos activation

Prefer Apple PhotoKit for this personal macOS MVP. It is implemented and keeps
the workflow local.

1. Run the signed bundle or development build on the home Mac.
2. Under **Settings > Photos**, start setup and grant **Full Access** in the
   macOS prompt. The current album connector does not operate with Limited Access.
3. Select a small album/scope, sync, verify owner detection, and explicitly
   confirm the owner.
4. Test disable, deletion, and restart. If denied, re-enable access under
   **System Settings > Privacy & Security > Photos**.

Apple reference:
https://developer.apple.com/documentation/photokit/requesting-authorization-to-access-photos

Google Photos is an alternative, not a full-library drop-in. Current Google
guidance uses the Picker API for user-selected media; older broad Library API
read tutorials are obsolete. A Google implementation needs a new EARS phase
covering Picker sessions, polling, bounded downloads, expiry, and deletion.

- https://developers.google.com/photos/picker/guides/get-started-picker
- https://developers.google.com/photos/library/guides/updates

## Next phases

After P12 acceptance:

1. Run a bounded live Gmail import and record sanitized interoperability evidence.
2. Activate PhotoKit with a small user-selected scope.
3. Reconcile purchase units with owner-confirmed garment observations.
4. Exercise outfit recommendations against the canonical catalog.
5. Keep try-on presentation-only and never claim fit or physical accuracy.

Retain EARS and generator -> independent review -> build -> evaluate. External
availability may be deferred, but privacy, atomicity, backup, deletion, replay,
and user authority may not be weakened.

## Repository hygiene

Before every push:

```bash
git diff --check
git status --short
git diff --cached --name-only
git grep -nE 'GOCSPX-|sk-[A-Za-z0-9_-]{20,}|gpuj[[:space:]]+cmhg'
```

Never commit `.env*`, OAuth tokens, API keys, app passwords, personal data,
databases, logs, private evals, or harness run output.

# ADR 0001: Desktop Packaging Boundary

Status: Accepted

## Context

The product requires native PhotoKit integration and local-first operation.
Bundling Python, PyTorch, CUDA-oriented models, or a localhost application
server would materially increase signing, notarization, update, and lifecycle
risk.

The current development Mac has no valid Developer ID Application identity and
no configured notarytool profile. It can produce an arm64 ad-hoc signed
development application, but that artifact is not notarizable.

## Decision

The production shell uses Tauri 2 with a React interface and Rust application
core. Production assets are bundled locally. The main window receives only the
generated `allow-get-runtime-info` application-command permission; no Tauri
core or plugin permission is granted. Remote navigation, remote IPC, shell,
opener, filesystem, HTTP, and model plugins are excluded.

Python remains development and evaluation tooling only. Optional future local
models must be separately downloaded, checksummed, removable, and isolated
behind a narrow provider process.

`P00-PKG-002` validates the ad-hoc signed development package. It does not
satisfy or supersede `P00-PKG-001`.

## Fallback: P00-PKG-001

- Failed condition: Developer ID and notary credentials are unavailable on the development Mac.
- Accepted fallback: Use `P00-PKG-002` to validate an arm64 ad-hoc signed local development package without claiming production distribution readiness.
- Owner action: The repository owner must provide Apple Developer Program access, signing identity, and notarization credentials.
- Unblock evidence: Produce a hardened-runtime Developer ID build, notarize and staple it, pass `codesign` and Gatekeeper checks, then install and launch it on a clean supported Mac.

## Blocked production evidence

`P00-PKG-001` remains `BLOCKED` until the repository owner provides:

1. Apple Developer Program access.
2. A Developer ID Application certificate available to the build keychain.
3. App-specific password or App Store Connect API credentials configured for
   `notarytool`.
4. A credentialed release build with hardened runtime.
5. Successful notarization submission and ticket stapling.
6. Successful `codesign`, `spctl`, and stapler validation.
7. Artifact transfer, installation, launch, and signature inspection on a
   clean supported Mac.

## Consequences

Development can verify package composition and local lifecycle immediately.
Production distribution, updater work, and any claim of notarization readiness
remain gated on `P00-PKG-001`.

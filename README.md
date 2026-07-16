# Wardrobe

Local-first personal wardrobe cataloging, purchase reconciliation, outfit
planning, and optional AI visualization for macOS.

The project is specification-first. Product work follows a
**generate -> review -> build -> evaluate** loop, and every phase is gated by
EARS requirements and recorded evidence.

## Current status

Phases P00 through P08 have accepted personal-MVP evidence. The packaged macOS
application supports local durable storage, manual catalog and folder imports,
receipt extraction and approved image retrieval, and immutable photo-scope
analysis with local Apple Vision person detection, explicit owner confirmation,
and reviewable source-crop fallbacks. It can reconcile owner-confirmed photos
against local wardrobe images and reviewed receipt lines while keeping the
final decision under user control, synchronize Gmail through OAuth with
Keychain-backed credentials, and create durable offline outfits with
deterministic collages. The grounded recommendation production path, disclosure
flow, strict validation, and fixed OpenAI adapter are implemented, but remote
recommendations remain disabled until the frozen 500-case live evaluation
passes. Experimental try-on now provides explicit privacy disclosure, a
restart-safe real image-edits queue, labeled local results, and complete
deletion accounting; live interoperability, segmentation quality, and
visual-quality studies remain deferred behind their exact feature gates. Final
production hardening remains in progress.

## Development workflow

Prerequisites:

- macOS with Xcode and its command-line tools
- a current stable Rust toolchain
- Node.js and npm
- Python 3

Prepare a fresh clone before running the checks:

```bash
npm ci --ignore-scripts
cargo fetch --locked
```

The production bundle is deliberately built with Cargo and npm in offline
mode. The preparation commands above populate the local dependency caches;
afterward, `make build` verifies the pinned supply-chain manifest and produces
the macOS application without downloading dependencies.

```bash
make check
make test
make build

# Create a work packet from an immutable phase-spec snapshot.
python3 tools/harness.py generate P00 \
  --objective "Prove PhotoKit import and resumable local processing" \
  --requirements P00-PHO-001 P00-JOB-001

# A reviewer records an independent decision.
python3 tools/harness.py review P00 <run-id> \
  --decision approve \
  --reviewer "<name>" \
  --notes "Scope and verification plan are sufficient."

# Build and evaluate only after approval.
python3 tools/harness.py build P00 <run-id>
python3 tools/harness.py evaluate P00 <run-id>
```

`evaluate` fails unless every requirement in the run's frozen snapshot has
passing evidence or an explicit disabled-feature deferral under the
personal-MVP policy. A deferred requirement is retained as `deferred_not_passed`
and cannot enable the corresponding production feature.

## Documentation

- [Specification guide](specs/README.md)
- [System requirements](specs/system.md)
- [Phase manifest](specs/phases/manifest.json)
- [P04 phase report](docs/phase-reports/P04.md)
- [P08 phase report](docs/phase-reports/P08.md)
- [Agent development rules](AGENTS.md)

## Privacy

Never commit personal photos, email, OAuth tokens, API keys, face embeddings,
model payloads, or private evaluation datasets. Synthetic and sanitized
fixtures belong in `tests/fixtures/`; private evaluations remain outside the
repository.

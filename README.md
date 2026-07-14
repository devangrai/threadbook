# Wardrobe

Local-first personal wardrobe cataloging, purchase reconciliation, outfit
planning, and optional AI visualization for macOS.

The project is specification-first. Product work follows a
**generate -> review -> build -> evaluate** loop, and every phase is gated by
EARS requirements and recorded evidence.

## Current status

The repository is in the specification and feasibility stage. No production
application code has been approved yet.

## Development workflow

```bash
make check
make test

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
passing evidence. A successful command or model response alone is not evidence
that a requirement has been satisfied.

## Documentation

- [Specification guide](specs/README.md)
- [System requirements](specs/system.md)
- [Phase manifest](specs/phases/manifest.json)
- [Agent development rules](AGENTS.md)

## Privacy

Never commit personal photos, email, OAuth tokens, API keys, face embeddings,
model payloads, or private evaluation datasets. Synthetic and sanitized
fixtures belong in `tests/fixtures/`; private evaluations remain outside the
repository.

# Specification Guide

Requirements use the Easy Approach to Requirements Syntax (EARS). Each
requirement is independently testable and has a stable identifier.

## Requirement shape

```markdown
### P01-DAT-001: Store immutable source assets
- Type: Event-driven
- Statement: When the system imports source bytes, the system shall store them
  as an immutable content-addressed blob.
- Verification: Integration test with duplicate and interrupted imports.
```

Statements must use one of these forms:

| Type | Required form |
|---|---|
| Ubiquitous | `The system shall ...` |
| Event-driven | `When ..., the system shall ...` |
| State-driven | `While ..., the system shall ...` |
| Optional | `Where ... is enabled, the system shall ...` |
| Unwanted | `If ..., the system shall ...` |

## Lifecycle

1. Requirements begin as a reviewed baseline.
2. `generate` snapshots the applicable system and phase requirements.
3. Review checks scope, dependencies, failure modes, and verification.
4. Build is permitted only for an approved snapshot.
5. Evaluation requires passing evidence for every snapshotted requirement.
6. A changed specification invalidates an existing work packet.

## Personal MVP profile

Each packet implements one usable vertical slice, receives one independent
review, and is evaluated with focused unit tests, one end-to-end smoke test,
and the full regression suite at the phase boundary. Missing external
credentials, notarization, genuine model packs, and clean-machine
certification are recorded as deferred limitations when a real local fallback
preserves privacy, atomicity, backups, deletion accounting, and user authority.
Deferred capabilities remain disabled and must not be reported as passed.

A work packet may select one or more phase requirements:

```bash
python3 tools/harness.py generate P00 \
  --objective "Prove the signed desktop package boundary" \
  --requirements P00-PKG-001
```

The snapshot retains the full phase context, but only selected requirements
require evidence for that packet. This allows small reviewed vertical slices
without weakening the phase baseline.

## Evidence contract

During evaluation, tests write one JSON document per requirement into the
directory provided by `HARNESS_EVIDENCE_DIR`:

```json
{
  "requirement_id": "P01-DAT-001",
  "status": "pass",
  "test": "asset_store::duplicate_import_is_idempotent",
  "recorded_at": "2026-07-14T20:00:00Z",
  "details": {
    "fixture": "duplicate-photo-set-v1"
  }
}
```

Evidence is run-specific. Reusing evidence from an older code, prompt, model,
or specification version is prohibited.

## Phase order

- `P00`: feasibility spikes
- `P01`: platform foundation
- `P02`: manual catalog and imports
- `P03`: receipt intelligence
- `P04`: photo analysis
- `P05`: reconciliation
- `P06`: production connectors
- `P07`: outfit assistant
- `P08`: try-on visualization
- `P09`: production hardening
- `P10`: Gmail to wardrobe
- `P11`: OpenAI receipt intelligence
- `P12`: receipt purchase unit promotion (highest current delivery priority)

## Delivery priorities

1. Complete the local reviewed-receipt to canonical-wardrobe workflow in P12.
2. Activate and acceptance-test personal Gmail OAuth and the bounded recent
   receipt backfill when user credentials and browser access are available.
3. Activate a personal photo connector and materialize selected owner photos.
4. Reconcile receipt purchase units with real garment observations while
   preserving user decisions and unmatched evidence.
5. Run outfit recommendations and presentation-only try-on against the
   resulting personal canonical catalog.

Unavailable external credentials, Photos authorization, notarization, genuine
segmentation models, and clean-machine certification remain explicit deferred
limitations and do not weaken local privacy, atomicity, backup, deletion, or
user-authority requirements.

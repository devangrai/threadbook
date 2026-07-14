# Traceability

The phase manifest defines dependency-level traceability:

```text
P00 feasibility
  -> P01 foundation
      -> P02 manual catalog/imports
          -> P03 receipts
          -> P04 photo analysis
              -> P05 reconciliation
                  -> P06 production connectors
                  -> P07 outfit assistant
                      -> P08 try-on
          P06 + P07 + P08
              -> P09 production hardening
```

Requirement-level traceability is generated from the EARS source documents:

```bash
python3 tools/harness.py trace
python3 tools/harness.py trace --output artifacts/traceability.json
```

The harness validates that:

- every requirement ID is globally unique;
- every phase requirement uses its phase prefix;
- every requirement has EARS type, statement, and verification fields;
- every manifest dependency exists and the graph is acyclic;
- generated work packets contain frozen requirement and source hashes;
- evaluation evidence maps one-to-one to required requirement IDs.

Implementation tests should include the requirement ID in their name, metadata,
or generated evidence so failures can be traced back to the specification.

# PhotoKit Acceptance Fixtures

Generate the two reviewed non-personal images into a new directory:

```sh
python3 generate.py --output /path/to/new/fixture-directory
```

Import both generated PNG files into the dedicated acceptance-test Photos
library. Keep `local.png` resident on the Mac. Configure `cloud.png` as the
network-required iCloud fixture before running the live evaluator.

The evaluator accepts only the exact IDs, dimensions, and SHA-256 values in
`manifest.json`. The generator is deterministic and uses no external assets.

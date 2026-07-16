# Exact-package PhotoKit smoke

The P06 evaluator invokes the single checked-in runner:

```sh
python3 native/photokit/scripts/p06_photokit_live_smoke.py
```

The evaluator supplies a private nonce, frozen source/packet hashes, and its
independently computed identity for the already-built
`target/release/bundle/macos/Wardrobe.app`. That identity covers the exact
Info.plist, executable, deterministic bundle aggregate, bundle identifier, and
designated requirement. The evaluator also requires strict deep code-signature
verification. The runner recomputes the identity before opening the app and
after relaunch, and returns the exact challenged values.

The runner generates the two reviewed P00 fixtures and guides the operator
through album setup and one stopped-app removal. Before and after relaunch, it
derives each retained CAS path from the validated database content hash and
verifies a unique regular non-symlink file with the exact database byte length
and SHA-256. It also verifies both database snapshots, real materialization
attempts, the startup trigger, and a synthetic catalog item whose assigned
evidence co-owns the exact fixture blobs.

The isolated application starts in Local only mode. Before connecting Apple
Photos, the operator must open Privacy, choose `Enable personal live`, and
confirm the disclosure. The runner then requires full Photos read access for
the exact packaged application identity.

Any existing Wardrobe application data and logs are atomically rotated out and
restored. A `preparing` / `isolated` / `restoring` crash journal permits
Keychain cleanup only while the smoke database is authoritative, then records
`restoring` before user data can return. Failure emits no acceptance record and
shows only an allowlisted stage plus instructions to remove synthetic Photos
fixtures and review Photos permission if the run changed it. Successful
standard output is exactly one nonce-bound `P06_PHOTOKIT_LIVE` record with no
PhotoKit identifiers, names, paths, image bytes, or personal metadata.

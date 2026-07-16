# OpenCV person-detection fixtures

These fixtures are unmodified files from the OpenCV `4.x` repository at tree
`2e778c52c1b8fdd8ae4c4b058feb653b90d31a33`. OpenCV is distributed under the
Apache License 2.0; see <https://github.com/opencv/opencv/blob/4.x/LICENSE>.
The images retain all embedded marks.

| File | OpenCV source | Git blob | SHA-256 |
| --- | --- | --- | --- |
| `basketball1.png` | `samples/data/basketball1.png` | `53b2dbaad183dedd35a67c92c29882ec28f6ca44` | `ba06f6701f7260998b430c39b6557f775497e6ce7b1a74f0b7ea6af371bf54a6` |
| `basketball2.png` | `samples/data/basketball2.png` | `1d069b965c004459e065caa6539ae4add17113fe` | `b3047772e0dc6c9d83c26f64894ca1a897f799f855c5574ac24b2ef934c2978e` |
| `building.jpg` | `samples/data/building.jpg` | `6056492f2fa97d2e57ed078b54b5afd8b6fbb6cb` | `742a1baad62ac82e91e718e77eedf7e85c2eddc4badfb8c87c6cbc86c45a8b07` |

Canonical source URLs use this form:
`https://github.com/opencv/opencv/blob/4.x/samples/data/<file>`.

The single-person test uses an in-memory `(0, 0, 220, 480)` crop of
`basketball1.png`; the checked-in source image remains unmodified.

The generated no-person linkage test remains independent so missing or
damaged fixtures cannot skip production Vision linkage.

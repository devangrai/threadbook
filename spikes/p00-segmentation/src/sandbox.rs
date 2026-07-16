use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SANDBOX_PROFILE_ID: &str = "deny_default_v1";
pub const SENTINELS: [&str; 8] = [
    "P00_PIXEL_SENTINEL",
    "P00_MASK_SENTINEL",
    "P00_LABEL_SENTINEL",
    "P00_SEED_SENTINEL",
    "P00_PATH_SENTINEL",
    "P00_TENSOR_SENTINEL",
    "P00_MODEL_SENTINEL",
    "P00_SECRET_SENTINEL",
];

pub const DENY_DEFAULT_PROFILE: &str = r#"(version 1)
(deny default)
(allow process-exec (literal "/frozen/provider-helper"))
(deny network*)
(deny file-write*)
(deny process-fork)
(deny process-info*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/frozen/model-pack"))
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxReview {
    pub profile_id: String,
    pub deny_default: bool,
    pub network_denied: bool,
    pub filesystem_writes_denied: bool,
    pub process_creation_denied_after_entry: bool,
    pub probe_executed: bool,
}

impl SandboxReview {
    pub fn reviewed_but_unexecuted() -> Self {
        Self {
            profile_id: SANDBOX_PROFILE_ID.into(),
            deny_default: DENY_DEFAULT_PROFILE.contains("(deny default)"),
            network_denied: DENY_DEFAULT_PROFILE.contains("(deny network*)"),
            filesystem_writes_denied: DENY_DEFAULT_PROFILE.contains("(deny file-write*)"),
            process_creation_denied_after_entry: DENY_DEFAULT_PROFILE
                .contains("(deny process-fork)"),
            probe_executed: false,
        }
    }

    pub fn acceptance_eligible(&self) -> bool {
        self.deny_default
            && self.network_denied
            && self.filesystem_writes_denied
            && self.process_creation_denied_after_entry
            && self.probe_executed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeakFinding {
    pub sentinel: &'static str,
    pub encoding: &'static str,
}

pub fn scan_for_sentinels(outputs: &[&[u8]]) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    for sentinel in SENTINELS {
        let encodings = [
            ("raw", sentinel.as_bytes().to_vec()),
            ("hex", hex(sentinel.as_bytes()).into_bytes()),
            ("base64", base64(sentinel.as_bytes()).into_bytes()),
            (
                "json_escaped",
                serde_json::to_string(sentinel)
                    .expect("sentinel JSON")
                    .trim_matches('"')
                    .as_bytes()
                    .to_vec(),
            ),
        ];
        let mut distinct_needles = BTreeSet::new();
        for (encoding, needle) in encodings {
            if distinct_needles.insert(needle.clone())
                && outputs.iter().any(|output| contains(output, &needle))
            {
                findings.push(LeakFinding { sentinel, encoding });
            }
        }
    }
    findings
}

pub fn content_free_diagnostic(
    request_handle: &str,
    dimensions: (u32, u32),
    duration_ms: u64,
    output_bytes: usize,
) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("request_handle", request_handle.to_owned()),
        ("width", dimensions.0.to_string()),
        ("height", dimensions.1.to_string()),
        ("duration_ms", duration_ms.to_string()),
        ("output_bytes", output_bytes.to_string()),
    ])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_profile_is_fail_closed_until_executed_on_acceptance_host() {
        let review = SandboxReview::reviewed_but_unexecuted();
        assert!(review.deny_default);
        assert!(review.network_denied);
        assert!(review.filesystem_writes_denied);
        assert!(!review.probe_executed);
        assert!(!review.acceptance_eligible());
    }

    #[test]
    fn scanner_detects_raw_hex_base64_and_escaped_sentinels() {
        let raw = SENTINELS[0].as_bytes();
        assert_eq!(scan_for_sentinels(&[raw]).len(), 1);
        let hex_value = hex(SENTINELS[1].as_bytes());
        assert!(scan_for_sentinels(&[hex_value.as_bytes()])
            .iter()
            .any(|finding| finding.sentinel == SENTINELS[1]));
        let base64_value = base64(SENTINELS[2].as_bytes());
        assert!(scan_for_sentinels(&[base64_value.as_bytes()])
            .iter()
            .any(|finding| finding.sentinel == SENTINELS[2]));
        assert!(scan_for_sentinels(&[b"request_handle=opaque-01 width=1024"]).is_empty());
    }

    #[test]
    fn diagnostics_have_only_content_free_fields() {
        let diagnostic = content_free_diagnostic("opaque-handle", (1024, 1024), 31, 900);
        assert_eq!(diagnostic.len(), 5);
        assert!(diagnostic.contains_key("request_handle"));
        assert!(!diagnostic.keys().any(|key| {
            [
                "pixel", "mask", "label", "seed", "path", "tensor", "model", "secret",
            ]
            .contains(key)
        }));
    }
}

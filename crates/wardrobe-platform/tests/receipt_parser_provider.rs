use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use wardrobe_core::{
    EvidenceStringV1, EvidenceU64V1, ReceiptEventKindV1, ReceiptEvidenceProvider,
    ReceiptFragmentKindV1, SourceId,
};
use wardrobe_platform::{parse_receipt_v1, LocalDeterministicReceiptProviderV1};

#[derive(Deserialize)]
struct Manifest {
    corpus: Corpus,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Corpus {
    message_count: usize,
    labeled_line_count: usize,
}

#[derive(Deserialize)]
struct Message {
    coverage: Vec<String>,
    eml: String,
    expected: ExpectedReceipt,
}

#[derive(Deserialize)]
struct ExpectedReceipt {
    merchant: Option<String>,
    order_identifier: Option<String>,
    purchase_date: Option<String>,
    currency: Option<String>,
    unsupported_fields: Vec<String>,
    lines: Vec<ExpectedLine>,
}

#[derive(Deserialize)]
struct ExpectedLine {
    event_kind: String,
    description: String,
    quantity: Option<u64>,
    unit_price_minor: Option<u64>,
    brand: Option<String>,
    sku: Option<String>,
    size: Option<String>,
    color: Option<String>,
    unsupported_fields: Vec<String>,
    source_quote: String,
}

#[test]
fn frozen_corpus_has_full_recall_valid_citations_and_no_unsupported_fabrication() {
    let manifest = load_manifest();
    assert_eq!(manifest.corpus.message_count, 24);
    assert_eq!(manifest.corpus.labeled_line_count, 48);
    assert_eq!(manifest.messages.len(), 24);

    let provider = LocalDeterministicReceiptProviderV1::new();
    let mut matched = 0_usize;
    let mut gold = 0_usize;
    let mut unsupported_failures = Vec::new();
    let mut citation_failures = Vec::new();
    let mut observed_coverage = BTreeSet::new();

    for (message_index, message) in manifest.messages.iter().enumerate() {
        observed_coverage.extend(message.coverage.iter().cloned());
        let parsed = parse_receipt_v1(source_id(message_index), message.eml.as_bytes()).unwrap();
        let first = provider.extract(&parsed).unwrap();
        let second = provider.extract(&parsed).unwrap();
        assert_eq!(
            first,
            second,
            "message {} replay changed",
            message_index + 1
        );
        if first.validate_against(&parsed).is_err() {
            citation_failures.push(message_index + 1);
        }

        compare_order_field(
            "merchant",
            &first.output.merchant,
            message.expected.merchant.as_deref(),
            &message.expected.unsupported_fields,
            message_index,
            &mut unsupported_failures,
        );
        compare_order_field(
            "order_identifier",
            &first.output.order_identifier,
            message.expected.order_identifier.as_deref(),
            &message.expected.unsupported_fields,
            message_index,
            &mut unsupported_failures,
        );
        compare_order_field(
            "purchase_date",
            &first.output.purchase_date,
            message.expected.purchase_date.as_deref(),
            &message.expected.unsupported_fields,
            message_index,
            &mut unsupported_failures,
        );
        compare_order_field(
            "currency",
            &first.output.currency,
            message.expected.currency.as_deref(),
            &message.expected.unsupported_fields,
            message_index,
            &mut unsupported_failures,
        );

        gold += message.expected.lines.len();
        assert_eq!(
            first.output.line_items.len(),
            message.expected.lines.len(),
            "message {} line count",
            message_index + 1
        );
        for (line_index, (actual, expected)) in first
            .output
            .line_items
            .iter()
            .zip(&message.expected.lines)
            .enumerate()
        {
            assert!(
                parsed
                    .fragments
                    .iter()
                    .any(|fragment| fragment.text.contains(&expected.source_quote)),
                "message {} line {} source quote did not survive normalization",
                message_index + 1,
                line_index + 1
            );
            let line_matches = actual.event_kind.value == expected_event(&expected.event_kind)
                && actual.description.value.as_deref() == Some(expected.description.as_str())
                && actual.quantity.value == expected.quantity
                && actual.unit_price_minor.value == expected.unit_price_minor
                && actual.variant.brand.value.as_deref() == expected.brand.as_deref()
                && actual.variant.sku.value.as_deref() == expected.sku.as_deref()
                && actual.variant.size.value.as_deref() == expected.size.as_deref()
                && actual.variant.color.value.as_deref() == expected.color.as_deref();
            matched += usize::from(line_matches);

            compare_line_unknown(
                "quantity",
                &actual.quantity,
                expected.quantity,
                &expected.unsupported_fields,
                message_index,
                line_index,
                &mut unsupported_failures,
            );
            compare_line_unknown(
                "unit_price_minor",
                &actual.unit_price_minor,
                expected.unit_price_minor,
                &expected.unsupported_fields,
                message_index,
                line_index,
                &mut unsupported_failures,
            );
            for (name, field, expected_value) in [
                ("brand", &actual.variant.brand, expected.brand.as_deref()),
                ("sku", &actual.variant.sku, expected.sku.as_deref()),
                ("size", &actual.variant.size, expected.size.as_deref()),
                ("color", &actual.variant.color, expected.color.as_deref()),
            ] {
                compare_line_string_unknown(
                    name,
                    field,
                    expected_value,
                    &expected.unsupported_fields,
                    message_index,
                    line_index,
                    &mut unsupported_failures,
                );
            }
        }

        assert_metadata_coverage(message, &parsed, message_index);
    }

    let recall = matched as f64 / gold as f64;
    eprintln!(
        "receipt corpus: matched={matched} gold={gold} recall={recall:.4} unsupported_failures={} citation_failures={}",
        unsupported_failures.len(),
        citation_failures.len()
    );
    assert!(recall >= 0.95, "item recall {recall:.4} is below 0.95");
    assert!(
        unsupported_failures.is_empty(),
        "unsupported-field failures: {unsupported_failures:?}"
    );
    assert!(
        citation_failures.is_empty(),
        "citation failures: {citation_failures:?}"
    );
    for required in [
        "plain_text",
        "html_table",
        "html_list",
        "multipart_alternative",
        "cid_metadata",
        "attachment_metadata",
        "purchase",
        "exchange",
        "return",
        "missing_fields",
        "repeated_quantities",
        "injection_text",
    ] {
        assert!(observed_coverage.contains(required));
    }
}

fn compare_order_field(
    name: &str,
    actual: &EvidenceStringV1,
    expected: Option<&str>,
    unsupported: &[String],
    message_index: usize,
    failures: &mut Vec<String>,
) {
    assert_eq!(
        actual.value.as_deref(),
        expected,
        "message {} order field {name}",
        message_index + 1
    );
    let named_unsupported = unsupported.iter().any(|field| field == name);
    if named_unsupported != expected.is_none()
        || (expected.is_none() && (!actual.citations.is_empty() || actual.value.is_some()))
    {
        failures.push(format!("message {} {name}", message_index + 1));
    }
}

fn compare_line_unknown(
    name: &str,
    actual: &EvidenceU64V1,
    expected: Option<u64>,
    unsupported: &[String],
    message_index: usize,
    line_index: usize,
    failures: &mut Vec<String>,
) {
    let named_unsupported = unsupported.iter().any(|field| field == name);
    if named_unsupported != expected.is_none()
        || (expected.is_none() && (!actual.citations.is_empty() || actual.value.is_some()))
    {
        failures.push(format!(
            "message {} line {} {name}",
            message_index + 1,
            line_index + 1
        ));
    }
}

fn compare_line_string_unknown(
    name: &str,
    actual: &EvidenceStringV1,
    expected: Option<&str>,
    unsupported: &[String],
    message_index: usize,
    line_index: usize,
    failures: &mut Vec<String>,
) {
    let named_unsupported = unsupported.iter().any(|field| field == name);
    if named_unsupported != expected.is_none()
        || (expected.is_none() && (!actual.citations.is_empty() || actual.value.is_some()))
    {
        failures.push(format!(
            "message {} line {} {name}",
            message_index + 1,
            line_index + 1
        ));
    }
}

fn assert_metadata_coverage(
    message: &Message,
    parsed: &wardrobe_core::ParsedReceiptEvidenceV1,
    message_index: usize,
) {
    if message.coverage.iter().any(|value| value == "cid_metadata") {
        assert!(
            parsed
                .fragments
                .iter()
                .any(|fragment| fragment.kind == ReceiptFragmentKindV1::CidMetadata),
            "message {} missing CID metadata",
            message_index + 1
        );
    }
    if message
        .coverage
        .iter()
        .any(|value| value == "attachment_metadata")
    {
        assert!(
            parsed
                .fragments
                .iter()
                .any(|fragment| fragment.kind == ReceiptFragmentKindV1::AttachmentMetadata),
            "message {} missing attachment metadata",
            message_index + 1
        );
    }
}

fn expected_event(value: &str) -> Option<ReceiptEventKindV1> {
    match value {
        "purchase" => Some(ReceiptEventKindV1::Purchase),
        "exchange" => Some(ReceiptEventKindV1::Exchange),
        "return" => Some(ReceiptEventKindV1::Return),
        _ => None,
    }
}

fn source_id(index: usize) -> SourceId {
    let mut bytes = [0_u8; 16];
    bytes[0..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    SourceId::new(Uuid::from_bytes(bytes)).unwrap()
}

fn load_manifest() -> Manifest {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/receipts/v1/manifest.json");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "a13dc0d6a28308ab01232b800f23a77119479cde4fe9db44f05a3102a69a5cac"
    );
    serde_json::from_slice(&bytes).unwrap()
}

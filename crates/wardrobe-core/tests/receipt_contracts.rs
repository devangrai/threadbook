use wardrobe_core::*;

fn parsed(text: &str) -> ParsedReceiptEvidenceV1 {
    let fragment = ReceiptFragmentV1 {
        fragment_id: ReceiptFragmentId::new_v4(),
        ordinal: 0,
        kind: ReceiptFragmentKindV1::PlainText,
        text: text.to_owned(),
        content_sha256: Sha256Digest::from_bytes(text.as_bytes()),
        metadata: None,
    };
    let mut parsed = ParsedReceiptEvidenceV1 {
        parse_id: ReceiptParseId::new_v4(),
        source_id: SourceId::new_v4(),
        raw_blob_sha256: Sha256Digest::from_bytes(b"raw receipt"),
        parser_revision: "mail-parser-v1".to_owned(),
        sanitizer_revision: "receipt-sanitizer-v1".to_owned(),
        canonical_input_sha256: Sha256Digest::from_bytes(b"placeholder"),
        fragments: vec![fragment],
    };
    parsed.canonical_input_sha256 = parsed.compute_canonical_input_sha256();
    parsed
}

fn citation(parsed: &ParsedReceiptEvidenceV1, quote: &str) -> FragmentCitationV1 {
    let fragment = &parsed.fragments[0];
    let start = fragment.text.find(quote).unwrap();
    let end = start + quote.len();
    FragmentCitationV1 {
        fragment_id: fragment.fragment_id,
        byte_start: start as u32,
        byte_end: end as u32,
        quote_sha256: Sha256Digest::from_bytes(quote.as_bytes()),
    }
}

fn known_string(parsed: &ParsedReceiptEvidenceV1, value: &str) -> EvidenceStringV1 {
    EvidenceStringV1 {
        value: Some(value.to_owned()),
        citations: vec![citation(parsed, value)],
    }
}

fn known_u64(parsed: &ParsedReceiptEvidenceV1, value: u64, quote: &str) -> EvidenceU64V1 {
    EvidenceU64V1 {
        value: Some(value),
        citations: vec![citation(parsed, quote)],
    }
}

fn unknown_string() -> EvidenceStringV1 {
    EvidenceStringV1 {
        value: None,
        citations: vec![],
    }
}

fn extraction(parsed: &ParsedReceiptEvidenceV1) -> ReceiptExtractionV1 {
    ReceiptExtractionV1 {
        schema_version: ReceiptExtractionSchemaV1::V1,
        merchant: known_string(parsed, "Example Shop"),
        order_identifier: unknown_string(),
        purchase_date: known_string(parsed, "2026-07-15"),
        currency: known_string(parsed, "USD"),
        line_items: vec![
            ReceiptLineItemExtractionV1 {
                description: known_string(parsed, "Blue Shirt"),
                event_kind: EvidenceEventKindV1 {
                    value: Some(ReceiptEventKindV1::Purchase),
                    citations: vec![citation(parsed, "Purchase")],
                },
                quantity: known_u64(parsed, 3, "Qty 3"),
                unit_price_minor: known_u64(parsed, 0, "$0.00"),
                variant: ReceiptVariantExtractionV1 {
                    brand: unknown_string(),
                    sku: unknown_string(),
                    size: known_string(parsed, "Large"),
                    color: known_string(parsed, "Blue"),
                },
            },
            ReceiptLineItemExtractionV1 {
                description: known_string(parsed, "Red Shirt"),
                event_kind: EvidenceEventKindV1 {
                    value: Some(ReceiptEventKindV1::Exchange),
                    citations: vec![citation(parsed, "Exchange")],
                },
                quantity: known_u64(parsed, 1, "Qty 1"),
                unit_price_minor: known_u64(parsed, 2500, "$25.00"),
                variant: ReceiptVariantExtractionV1 {
                    brand: unknown_string(),
                    sku: unknown_string(),
                    size: known_string(parsed, "Medium"),
                    color: known_string(parsed, "Red"),
                },
            },
            ReceiptLineItemExtractionV1 {
                description: known_string(parsed, "Black Belt"),
                event_kind: EvidenceEventKindV1 {
                    value: Some(ReceiptEventKindV1::Return),
                    citations: vec![citation(parsed, "Return")],
                },
                quantity: known_u64(parsed, 2, "Qty 2"),
                unit_price_minor: known_u64(parsed, 1900, "$19.00"),
                variant: ReceiptVariantExtractionV1 {
                    brand: unknown_string(),
                    sku: unknown_string(),
                    size: unknown_string(),
                    color: known_string(parsed, "Black"),
                },
            },
        ],
    }
}

fn fixture_text() -> &'static str {
    "Example Shop\n2026-07-15\nUSD\nPurchase Blue Shirt Qty 3 $0.00 Large Blue\n\
     Exchange Red Shirt Qty 1 $25.00 Medium Red\n\
     Return Black Belt Qty 2 $19.00 Black"
}

#[test]
fn strict_receipt_decoding_rejects_unknown_missing_and_wrong_version_fields() {
    let request = serde_json::json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "source_id": SourceId::new_v4()
    });
    assert!(serde_json::from_value::<AnalyzeReceiptV1Request>(request.clone()).is_ok());

    let mut unknown = request.clone();
    unknown["force"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AnalyzeReceiptV1Request>(unknown).is_err());

    let mut wrong_version = request;
    wrong_version["schema_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<AnalyzeReceiptV1Request>(wrong_version).is_err());

    let parsed = parsed(fixture_text());
    let mut output = serde_json::to_value(extraction(&parsed)).unwrap();
    output["line_items"][0]["variant"]["brand"]["invented"] = serde_json::json!("value");
    assert!(serde_json::from_value::<ReceiptExtractionV1>(output).is_err());

    let missing_explicit_null = serde_json::json!({"citations": []});
    assert!(serde_json::from_value::<EvidenceStringV1>(missing_explicit_null).is_err());
}

#[test]
fn known_and_unknown_evidence_require_opposite_citation_shapes() {
    let parsed = parsed(fixture_text());
    let mut output = extraction(&parsed);
    assert!(output.validate_against(&parsed).is_ok());
    assert_eq!(output.order_identifier.value, None);
    assert!(output.order_identifier.citations.is_empty());
    assert_eq!(output.line_items[0].variant.brand.value, None);

    output.merchant.citations.clear();
    assert_eq!(
        output.validate_against(&parsed).unwrap_err().field,
        SafeFieldV1::ReceiptCitation
    );

    let mut output = extraction(&parsed);
    output.order_identifier.citations = vec![citation(&parsed, "Example Shop")];
    assert_eq!(
        output.validate_against(&parsed).unwrap_err().field,
        SafeFieldV1::ReceiptCitation
    );

    let mut output = extraction(&parsed);
    output.currency.value = Some("ZZZ".to_owned());
    assert_eq!(
        output.validate_against(&parsed).unwrap_err().field,
        SafeFieldV1::ReceiptEvidence
    );

    let mut output = extraction(&parsed);
    let duplicate = output.line_items[0].description.citations[0].clone();
    output.line_items[0].description.citations.push(duplicate);
    assert_eq!(
        output.validate_against(&parsed).unwrap_err().field,
        SafeFieldV1::ReceiptCitation
    );
}

#[test]
fn citations_require_current_nonempty_utf8_spans_and_exact_quote_hashes() {
    let parsed = parsed("é Purchase Blue Shirt");
    let mut valid = citation(&parsed, "Blue Shirt");
    assert!(parsed.validate_citation(&valid).is_ok());

    valid.quote_sha256 = Sha256Digest::from_bytes(b"different");
    assert_eq!(
        parsed.validate_citation(&valid).unwrap_err().field,
        SafeFieldV1::ReceiptCitation
    );

    let mut invalid_boundary = citation(&parsed, "Purchase");
    invalid_boundary.byte_start = 1;
    assert!(parsed.validate_citation(&invalid_boundary).is_err());

    let empty = FragmentCitationV1 {
        fragment_id: parsed.fragments[0].fragment_id,
        byte_start: 2,
        byte_end: 2,
        quote_sha256: Sha256Digest::from_bytes(b""),
    };
    assert!(parsed.validate_citation(&empty).is_err());

    let foreign = FragmentCitationV1 {
        fragment_id: ReceiptFragmentId::new_v4(),
        ..citation(&parsed, "Purchase")
    };
    assert!(parsed.validate_citation(&foreign).is_err());
}

#[test]
fn order_line_variant_and_catalog_identities_stay_distinct() {
    let order_id = ReceiptOrderEvidenceId::new_v4();
    let line_id = ReceiptOrderLineId::new_v4();
    let variant_id = ReceiptVariantEvidenceId::new_v4();
    let item_id = ItemId::new_v4();

    let encoded = [
        order_id.to_string(),
        line_id.to_string(),
        variant_id.to_string(),
        item_id.to_string(),
    ];
    let mut unique = encoded.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 4);

    let parsed = parsed(fixture_text());
    let output = extraction(&parsed);
    assert!(output.validate_against(&parsed).is_ok());
    assert_eq!(output.line_items[0].quantity.value, Some(3));
    assert_eq!(output.line_items[0].unit_price_minor.value, Some(0));
    assert_eq!(
        output.line_items[1].event_kind.value,
        Some(ReceiptEventKindV1::Exchange)
    );
    assert_eq!(
        output.line_items[2].event_kind.value,
        Some(ReceiptEventKindV1::Return)
    );
}

fn corrected_order() -> CorrectedReceiptOrderV1 {
    CorrectedReceiptOrderV1 {
        order_evidence_id: ReceiptOrderEvidenceId::new_v4(),
        merchant: Some("Corrected Shop".to_owned()),
        order_identifier: None,
        purchase_date: Some("2026-07-15".to_owned()),
        currency: Some("USD".to_owned()),
        line_items: vec![CorrectedReceiptOrderLineV1 {
            order_line_id: ReceiptOrderLineId::new_v4(),
            description: Some("Blue Shirt".to_owned()),
            event_kind: Some(ReceiptEventKindV1::Purchase),
            quantity: Some(2),
            unit_price_minor: None,
            variant: CorrectedReceiptVariantV1 {
                variant_evidence_id: ReceiptVariantEvidenceId::new_v4(),
                brand: None,
                sku: None,
                size: Some("L".to_owned()),
                color: None,
            },
        }],
    }
}

#[test]
fn review_actions_require_a_complete_correction_only_for_correct() {
    let corrected = corrected_order();
    let base = ReviewReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        order_evidence_id: corrected.order_evidence_id,
        action: ReceiptReviewActionV1::Correct,
        corrected_order: Some(corrected.clone()),
        expected_receipt_revision: 4,
    };
    assert!(base.validate().is_ok());

    let missing = ReviewReceiptV1Request {
        corrected_order: None,
        ..base.clone()
    };
    assert_eq!(
        missing.validate().unwrap_err().field,
        SafeFieldV1::ReceiptReviewAction
    );

    for action in [
        ReceiptReviewActionV1::Confirm,
        ReceiptReviewActionV1::Reject,
        ReceiptReviewActionV1::Defer,
    ] {
        let forbidden = ReviewReceiptV1Request {
            action,
            ..base.clone()
        };
        assert_eq!(
            forbidden.validate().unwrap_err().field,
            SafeFieldV1::ReceiptReviewAction
        );
    }

    let wrong_order = ReviewReceiptV1Request {
        order_evidence_id: ReceiptOrderEvidenceId::new_v4(),
        ..base
    };
    assert!(wrong_order.validate().is_err());
}

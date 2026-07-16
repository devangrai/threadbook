use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wardrobe_core::*;

fn parsed() -> ParsedReceiptEvidenceV1 {
    let text = "Shop\nOrder X-1\n2026-07-15\nUSD\n\
                Purchase Blue Shirt Qty 2 $25.00 Brand Acme SKU A1 Size Medium Color Blue";
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
        raw_blob_sha256: Sha256Digest::from_bytes(b"raw"),
        parser_revision: "parser-v1".to_owned(),
        sanitizer_revision: "sanitizer-v1".to_owned(),
        canonical_input_sha256: Sha256Digest::from_bytes(b"placeholder"),
        fragments: vec![fragment],
    };
    parsed.canonical_input_sha256 = parsed.compute_canonical_input_sha256();
    parsed
}

fn citation(parsed: &ParsedReceiptEvidenceV1, quote: &str) -> FragmentCitationV1 {
    let start = parsed.fragments[0].text.find(quote).unwrap();
    FragmentCitationV1 {
        fragment_id: parsed.fragments[0].fragment_id,
        byte_start: start as u32,
        byte_end: (start + quote.len()) as u32,
        quote_sha256: Sha256Digest::from_bytes(quote.as_bytes()),
    }
}

fn string_evidence(parsed: &ParsedReceiptEvidenceV1, value: &str) -> EvidenceStringV1 {
    EvidenceStringV1 {
        value: Some(value.to_owned()),
        citations: vec![citation(parsed, value)],
    }
}

fn envelope(parsed: &ParsedReceiptEvidenceV1) -> ReceiptExtractionEnvelopeV1 {
    ReceiptExtractionEnvelopeV1 {
        processing: ReceiptProcessingMetadataV1 {
            provider_id: "local-deterministic".to_owned(),
            provider_revision: "provider-v1".to_owned(),
            extraction_schema: RECEIPT_EXTRACTION_SCHEMA_V1.to_owned(),
            extraction_schema_sha256: Sha256Digest::parse(
                RECEIPT_EXTRACTION_SCHEMA_SHA256_V1.to_owned(),
            )
            .unwrap(),
            ruleset_revision: "rules-v1".to_owned(),
            ruleset_sha256: Sha256Digest::from_bytes(b"rules-v1"),
            parameters: ReceiptProviderParametersV1 {
                deterministic: true,
                temperature_milli: 0,
                locale: Some("en-US".to_owned()),
            },
            canonical_input_sha256: parsed.canonical_input_sha256.clone(),
            parent_source_id: parsed.source_id,
            parent_source_sha256: parsed.raw_blob_sha256.clone(),
            fragment_sha256: parsed
                .fragments
                .iter()
                .map(|fragment| fragment.content_sha256.clone())
                .collect(),
        },
        output: ReceiptExtractionV1 {
            schema_version: ReceiptExtractionSchemaV1::V1,
            merchant: string_evidence(parsed, "Shop"),
            order_identifier: string_evidence(parsed, "X-1"),
            purchase_date: string_evidence(parsed, "2026-07-15"),
            currency: string_evidence(parsed, "USD"),
            line_items: vec![ReceiptLineItemExtractionV1 {
                description: string_evidence(parsed, "Blue Shirt"),
                event_kind: EvidenceEventKindV1 {
                    value: Some(ReceiptEventKindV1::Purchase),
                    citations: vec![citation(parsed, "Purchase")],
                },
                quantity: EvidenceU64V1 {
                    value: Some(2),
                    citations: vec![citation(parsed, "Qty 2")],
                },
                unit_price_minor: EvidenceU64V1 {
                    value: Some(2500),
                    citations: vec![citation(parsed, "$25.00")],
                },
                variant: ReceiptVariantExtractionV1 {
                    brand: string_evidence(parsed, "Acme"),
                    sku: string_evidence(parsed, "A1"),
                    size: string_evidence(parsed, "Medium"),
                    color: string_evidence(parsed, "Blue"),
                },
            }],
        },
    }
}

fn review_head(
    order_evidence_id: ReceiptOrderEvidenceId,
    receipt_revision: u64,
) -> ReceiptReviewHeadV1 {
    ReceiptReviewHeadV1 {
        state: ReceiptStateV1::Confirmed,
        decision: ReceiptReviewDecisionV1 {
            decision_id: ReceiptReviewDecisionId::new_v4(),
            order_evidence_id,
            action: ReceiptReviewActionV1::Confirm,
            corrected_order: None,
            receipt_revision,
            created_at: "2026-07-15T03:00:00Z".to_owned(),
        },
    }
}

fn order(
    parsed: &ParsedReceiptEvidenceV1,
    envelope: &ReceiptExtractionEnvelopeV1,
    order_evidence_id: ReceiptOrderEvidenceId,
    review_head: Option<ReceiptReviewHeadV1>,
) -> ReceiptOrderEvidenceV1 {
    let line = &envelope.output.line_items[0];
    ReceiptOrderEvidenceV1 {
        order_evidence_id,
        extraction_run_id: ReceiptExtractionRunId::new_v4(),
        source_id: parsed.source_id,
        parse_id: parsed.parse_id,
        merchant: envelope.output.merchant.clone(),
        order_identifier: envelope.output.order_identifier.clone(),
        purchase_date: envelope.output.purchase_date.clone(),
        currency: envelope.output.currency.clone(),
        line_items: vec![ReceiptOrderLineV1 {
            order_line_id: ReceiptOrderLineId::new_v4(),
            line_number: 1,
            description: line.description.clone(),
            event_kind: line.event_kind.clone(),
            quantity: line.quantity.clone(),
            unit_price_minor: line.unit_price_minor.clone(),
            variant: ReceiptVariantEvidenceV1 {
                variant_evidence_id: ReceiptVariantEvidenceId::new_v4(),
                brand: line.variant.brand.clone(),
                sku: line.variant.sku.clone(),
                size: line.variant.size.clone(),
                color: line.variant.color.clone(),
            },
        }],
        review_head,
    }
}

fn analyze_response(
    request: &AnalyzeReceiptV1Request,
    parsed: &ParsedReceiptEvidenceV1,
    envelope: &ReceiptExtractionEnvelopeV1,
    order: ReceiptOrderEvidenceV1,
    replay_status: ReplayStatusV1,
) -> AnalyzeReceiptV1Response {
    AnalyzeReceiptV1Response {
        schema_version: 1,
        request_id: request.request_id,
        parsed: parsed.clone(),
        state: order.state(),
        order,
        processing: envelope.processing.clone(),
        receipt_revision: 2,
        evidence_generation: 7,
        replay_status,
    }
}

#[derive(Clone)]
struct Provider {
    envelope: ReceiptExtractionEnvelopeV1,
    calls: Rc<Cell<usize>>,
}

impl ReceiptEvidenceProvider for Provider {
    fn extract(
        &self,
        _parsed: &ParsedReceiptEvidenceV1,
    ) -> ReceiptProviderResult<ReceiptExtractionEnvelopeV1> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.envelope.clone())
    }
}

struct FailingProvider {
    error: ReceiptProviderError,
    calls: Rc<Cell<usize>>,
}

impl ReceiptEvidenceProvider for FailingProvider {
    fn extract(
        &self,
        _parsed: &ParsedReceiptEvidenceV1,
    ) -> ReceiptProviderResult<ReceiptExtractionEnvelopeV1> {
        self.calls.set(self.calls.get() + 1);
        Err(self.error)
    }
}

struct ReceiptDatabase {
    plan: RefCell<ReceiptAnalysisPlanV1>,
    commit_response: RefCell<AnalyzeReceiptV1Response>,
    review_response: RefCell<Option<ReviewReceiptV1Response>>,
    commit_calls: Cell<usize>,
    failure_records: RefCell<
        Vec<(
            RequestId,
            SourceId,
            ReceiptParseId,
            ReceiptAnalysisFailureV1,
        )>,
    >,
}

impl ReceiptPort for ReceiptDatabase {
    fn list_receipts(
        &self,
        request: &ListReceiptsV1Request,
    ) -> ReceiptPortResult<ListReceiptsV1Response> {
        Ok(ListReceiptsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            receipts: vec![],
            total_count: 0,
            receipt_revision: 0,
            evidence_generation: 0,
            next_cursor: None,
        })
    }

    fn prepare_receipt_analysis(
        &self,
        _request: &AnalyzeReceiptV1Request,
    ) -> ReceiptPortResult<ReceiptAnalysisPlanV1> {
        Ok(self.plan.borrow().clone())
    }

    fn commit_receipt_analysis(
        &self,
        _request: &AnalyzeReceiptV1Request,
        _parsed: &ParsedReceiptEvidenceV1,
        _envelope: &ReceiptExtractionEnvelopeV1,
        _preserved_review_head: Option<&ReceiptReviewHeadV1>,
    ) -> ReceiptPortResult<AnalyzeReceiptV1Response> {
        self.commit_calls.set(self.commit_calls.get() + 1);
        Ok(self.commit_response.borrow().clone())
    }

    fn record_receipt_analysis_failure(
        &self,
        request: &AnalyzeReceiptV1Request,
        parsed: &ParsedReceiptEvidenceV1,
        failure: ReceiptAnalysisFailureV1,
    ) -> ReceiptPortResult<ReceiptAnalysisFailureV1> {
        if request.source_id != parsed.source_id {
            return Err(ReceiptPortError::new(ReceiptPortErrorKind::DataIntegrity));
        }
        self.failure_records.borrow_mut().push((
            request.request_id,
            request.source_id,
            parsed.parse_id,
            failure,
        ));
        Ok(failure)
    }

    fn review_receipt_and_append_decision(
        &self,
        _request: &ReviewReceiptV1Request,
    ) -> ReceiptPortResult<ReviewReceiptV1Response> {
        self.review_response
            .borrow()
            .clone()
            .ok_or_else(|| ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }
}

#[test]
fn malformed_provider_output_is_rejected_before_persistence() {
    let parsed = parsed();
    let mut malformed = envelope(&parsed);
    malformed.output.line_items[0].description.citations[0].quote_sha256 =
        Sha256Digest::from_bytes(b"wrong quote");
    let request = AnalyzeReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: parsed.source_id,
    };
    let placeholder_order = order(
        &parsed,
        &envelope(&parsed),
        ReceiptOrderEvidenceId::new_v4(),
        None,
    );
    let database = ReceiptDatabase {
        plan: RefCell::new(ReceiptAnalysisPlanV1::Extract {
            parsed: parsed.clone(),
            preserved_review_head: None,
        }),
        commit_response: RefCell::new(analyze_response(
            &request,
            &parsed,
            &envelope(&parsed),
            placeholder_order,
            ReplayStatusV1::Created,
        )),
        review_response: RefCell::new(None),
        commit_calls: Cell::new(0),
        failure_records: RefCell::new(vec![]),
    };
    let calls = Rc::new(Cell::new(0));
    let service = ApplicationService::new(database, (), ()).with_receipt_provider(Provider {
        envelope: malformed,
        calls: calls.clone(),
    });

    let error = service.analyze_receipt_v1(request.clone()).unwrap_err();

    assert_eq!(error.code, ErrorCodeV1::MalformedProviderOutput);
    assert_eq!(calls.get(), 1);
    assert_eq!(service.database().commit_calls.get(), 0);
    assert_eq!(
        service.database().failure_records.borrow().as_slice(),
        &[(
            request.request_id,
            request.source_id,
            parsed.parse_id,
            ReceiptAnalysisFailureV1::OutputValidationFailed,
        )]
    );
}

#[test]
fn provider_failure_is_recorded_and_exact_failure_replay_bypasses_provider() {
    let parsed = parsed();
    let envelope = envelope(&parsed);
    let request = AnalyzeReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: parsed.source_id,
    };
    let placeholder = analyze_response(
        &request,
        &parsed,
        &envelope,
        order(&parsed, &envelope, ReceiptOrderEvidenceId::new_v4(), None),
        ReplayStatusV1::Created,
    );
    let database = ReceiptDatabase {
        plan: RefCell::new(ReceiptAnalysisPlanV1::Extract {
            parsed: parsed.clone(),
            preserved_review_head: None,
        }),
        commit_response: RefCell::new(placeholder),
        review_response: RefCell::new(None),
        commit_calls: Cell::new(0),
        failure_records: RefCell::new(vec![]),
    };
    let calls = Rc::new(Cell::new(0));
    let service =
        ApplicationService::new(database, (), ()).with_receipt_provider(FailingProvider {
            error: ReceiptProviderError::new(ReceiptProviderErrorKind::Unavailable),
            calls: calls.clone(),
        });

    let error = service.analyze_receipt_v1(request.clone()).unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::ProviderUnavailable);
    assert_eq!(calls.get(), 1);
    assert_eq!(service.database().commit_calls.get(), 0);
    assert_eq!(
        service.database().failure_records.borrow().as_slice(),
        &[(
            request.request_id,
            request.source_id,
            parsed.parse_id,
            ReceiptAnalysisFailureV1::ProviderUnavailable,
        )]
    );

    *service.database().plan.borrow_mut() =
        ReceiptAnalysisPlanV1::ReplayFailure(ReceiptAnalysisFailureV1::ProviderUnavailable);
    let replay_error = service.analyze_receipt_v1(request).unwrap_err();
    assert_eq!(replay_error, error);
    assert_eq!(calls.get(), 1);
    assert_eq!(service.database().failure_records.borrow().len(), 1);
}

#[test]
fn automated_rerun_cannot_clear_a_user_review_head() {
    let parsed = parsed();
    let envelope = envelope(&parsed);
    let request = AnalyzeReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: parsed.source_id,
    };
    let order_id = ReceiptOrderEvidenceId::new_v4();
    let preserved = review_head(order_id, 2);
    let cleared_order = order(&parsed, &envelope, order_id, None);
    let database = ReceiptDatabase {
        plan: RefCell::new(ReceiptAnalysisPlanV1::Extract {
            parsed: parsed.clone(),
            preserved_review_head: Some(preserved.clone()),
        }),
        commit_response: RefCell::new(analyze_response(
            &request,
            &parsed,
            &envelope,
            cleared_order,
            ReplayStatusV1::Created,
        )),
        review_response: RefCell::new(None),
        commit_calls: Cell::new(0),
        failure_records: RefCell::new(vec![]),
    };
    let service = ApplicationService::new(database, (), ()).with_receipt_provider(Provider {
        envelope: envelope.clone(),
        calls: Rc::new(Cell::new(0)),
    });

    let error = service.analyze_receipt_v1(request.clone()).unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);

    let preserved_order = order(&parsed, &envelope, order_id, Some(preserved.clone()));
    *service.database().commit_response.borrow_mut() = analyze_response(
        &request,
        &parsed,
        &envelope,
        preserved_order,
        ReplayStatusV1::Created,
    );
    let response = service.analyze_receipt_v1(request).unwrap();
    assert_eq!(response.order.review_head, Some(preserved));
    assert_eq!(response.state, ReceiptStateV1::Confirmed);
}

#[test]
fn exact_analysis_replay_bypasses_provider_and_preserves_response() {
    let parsed = parsed();
    let envelope = envelope(&parsed);
    let request = AnalyzeReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: parsed.source_id,
    };
    let replay = analyze_response(
        &request,
        &parsed,
        &envelope,
        order(&parsed, &envelope, ReceiptOrderEvidenceId::new_v4(), None),
        ReplayStatusV1::Replayed,
    );
    let database = ReceiptDatabase {
        plan: RefCell::new(ReceiptAnalysisPlanV1::Replay(replay.clone())),
        commit_response: RefCell::new(replay.clone()),
        review_response: RefCell::new(None),
        commit_calls: Cell::new(0),
        failure_records: RefCell::new(vec![]),
    };
    let calls = Rc::new(Cell::new(0));
    let service = ApplicationService::new(database, (), ()).with_receipt_provider(Provider {
        envelope,
        calls: calls.clone(),
    });

    assert_eq!(service.analyze_receipt_v1(request).unwrap(), replay);
    assert_eq!(calls.get(), 0);
    assert_eq!(service.database().commit_calls.get(), 0);
}

#[test]
fn review_service_enforces_cas_and_exact_decision_response() {
    let parsed = parsed();
    let envelope = envelope(&parsed);
    let order_id = ReceiptOrderEvidenceId::new_v4();
    let request = ReviewReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        order_evidence_id: order_id,
        action: ReceiptReviewActionV1::Confirm,
        corrected_order: None,
        expected_receipt_revision: 3,
    };
    let head = review_head(order_id, 4);
    let reviewed_order = order(&parsed, &envelope, order_id, Some(head.clone()));
    let response = ReviewReceiptV1Response {
        schema_version: 1,
        request_id: request.request_id,
        order: reviewed_order,
        decision: head.decision,
        new_receipt_revision: 4,
        evidence_generation: 7,
        replay_status: ReplayStatusV1::Created,
    };
    let analyze = AnalyzeReceiptV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: parsed.source_id,
    };
    let database = ReceiptDatabase {
        plan: RefCell::new(ReceiptAnalysisPlanV1::Extract {
            parsed: parsed.clone(),
            preserved_review_head: None,
        }),
        commit_response: RefCell::new(analyze_response(
            &analyze,
            &parsed,
            &envelope,
            order(&parsed, &envelope, ReceiptOrderEvidenceId::new_v4(), None),
            ReplayStatusV1::Created,
        )),
        review_response: RefCell::new(Some(response.clone())),
        commit_calls: Cell::new(0),
        failure_records: RefCell::new(vec![]),
    };
    let service = ApplicationService::new(database, (), ()).with_receipt_provider(Provider {
        envelope,
        calls: Rc::new(Cell::new(0)),
    });

    assert_eq!(
        service.review_receipt_v1(request.clone()).unwrap(),
        response
    );

    let mut corrupt = response;
    corrupt.new_receipt_revision = 5;
    *service.database().review_response.borrow_mut() = Some(corrupt);
    assert_eq!(
        service.review_receipt_v1(request).unwrap_err().code,
        ErrorCodeV1::DataIntegrity
    );
}

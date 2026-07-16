use crate::cost::Usage;
use crate::model::{EvidenceInteger, EvidenceString, GarmentLineObservation, ReceiptObservationV1};
use crate::transport::HttpResponse;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Success {
    pub observation: ReceiptObservationV1,
    pub response_id: String,
    pub returned_model: String,
    pub usage: Usage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub response_id: String,
    pub returned_model: String,
    pub usage: Usage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub retryable: bool,
    pub retry_after_seconds: Option<u64>,
}

impl Failure {
    pub fn new(kind: FailureKind, retryable: bool) -> Self {
        Self {
            kind,
            retryable,
            retry_after_seconds: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    InvalidApproval,
    Cancellation,
    RequestConflict,
    TimeoutRemoteOutcomeUnknown,
    Transport,
    Authentication,
    RateLimit,
    Provider5xx,
    ClientHttp,
    IncompleteResponse,
    ProtocolViolation,
    MalformedJson,
    SchemaViolation,
    SourceReferenceViolation,
    CostUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    Success(Success),
    Refusal(Refusal),
    Failure(Failure),
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedResponse {
    pub outcome: ProviderOutcome,
    pub response_id: Option<String>,
    pub returned_model: Option<String>,
    pub usage: Option<Usage>,
}

pub(crate) fn parse_response(
    response: &HttpResponse,
    submitted_sources: &BTreeSet<String>,
) -> ParsedResponse {
    if !(200..300).contains(&response.status) {
        return ParsedResponse {
            outcome: ProviderOutcome::Failure(http_failure(response)),
            response_id: None,
            returned_model: None,
            usage: None,
        };
    }

    let value: Value = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(_) => return failed(FailureKind::MalformedJson),
    };
    let Some(object) = value.as_object() else {
        return failed(FailureKind::ProtocolViolation);
    };
    let response_id = required_safe_string(object, "id");
    let returned_model = required_safe_string(object, "model");
    let (Some(response_id), Some(returned_model)) = (response_id, returned_model) else {
        return failed(FailureKind::ProtocolViolation);
    };
    let usage = match parse_usage(object.get("usage")) {
        Some(usage) => usage,
        None => {
            return failed_with_metadata(
                FailureKind::ProtocolViolation,
                response_id,
                returned_model,
                None,
            );
        }
    };
    if usage.cached_input_tokens != 0 || usage.cache_write_tokens != 0 {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    }

    if object.get("status").and_then(Value::as_str) != Some("completed") {
        return failed_with_metadata(
            FailureKind::IncompleteResponse,
            response_id,
            returned_model,
            Some(usage),
        );
    }

    let Some(output) = object.get("output").and_then(Value::as_array) else {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    };
    let messages = output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("message"))
        .collect::<Vec<_>>();
    let only_supported_outputs = output.iter().all(|item| {
        matches!(
            item.get("type").and_then(Value::as_str),
            Some("message" | "reasoning")
        )
    });
    if messages.len() != 1 || !only_supported_outputs {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    }
    let message = messages[0];
    if message.get("role").and_then(Value::as_str) != Some("assistant")
        || message.get("status").and_then(Value::as_str) != Some("completed")
    {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    }
    let Some(content) = message.get("content").and_then(Value::as_array) else {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    };
    if content.len() != 1 {
        return failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        );
    }
    match content[0].get("type").and_then(Value::as_str) {
        Some("refusal") if content[0].get("refusal").and_then(Value::as_str).is_some() => {
            ParsedResponse {
                outcome: ProviderOutcome::Refusal(Refusal {
                    response_id: response_id.clone(),
                    returned_model: returned_model.clone(),
                    usage,
                }),
                response_id: Some(response_id),
                returned_model: Some(returned_model),
                usage: Some(usage),
            }
        }
        Some("output_text") => {
            let Some(text) = content[0].get("text").and_then(Value::as_str) else {
                return failed_with_metadata(
                    FailureKind::ProtocolViolation,
                    response_id,
                    returned_model,
                    Some(usage),
                );
            };
            let observation_value: Value = match serde_json::from_str(text) {
                Ok(value) => value,
                Err(_) => {
                    return failed_with_metadata(
                        FailureKind::MalformedJson,
                        response_id,
                        returned_model,
                        Some(usage),
                    );
                }
            };
            if !validate_receipt_schema(&observation_value) {
                return failed_with_metadata(
                    FailureKind::SchemaViolation,
                    response_id,
                    returned_model,
                    Some(usage),
                );
            }
            let observation: ReceiptObservationV1 = match serde_json::from_value(observation_value)
            {
                Ok(observation) => observation,
                Err(_) => {
                    return failed_with_metadata(
                        FailureKind::SchemaViolation,
                        response_id,
                        returned_model,
                        Some(usage),
                    );
                }
            };
            if !valid_source_references(&observation, submitted_sources) {
                return failed_with_metadata(
                    FailureKind::SourceReferenceViolation,
                    response_id,
                    returned_model,
                    Some(usage),
                );
            }
            ParsedResponse {
                outcome: ProviderOutcome::Success(Success {
                    observation,
                    response_id: response_id.clone(),
                    returned_model: returned_model.clone(),
                    usage,
                }),
                response_id: Some(response_id),
                returned_model: Some(returned_model),
                usage: Some(usage),
            }
        }
        _ => failed_with_metadata(
            FailureKind::ProtocolViolation,
            response_id,
            returned_model,
            Some(usage),
        ),
    }
}

fn http_failure(response: &HttpResponse) -> Failure {
    match response.status {
        401 | 403 => Failure::new(FailureKind::Authentication, false),
        429 => Failure {
            kind: FailureKind::RateLimit,
            retryable: true,
            retry_after_seconds: response
                .header("retry-after")
                .and_then(|value| value.parse().ok()),
        },
        500..=599 => Failure::new(FailureKind::Provider5xx, true),
        _ => Failure::new(FailureKind::ClientHttp, false),
    }
}

fn failed(kind: FailureKind) -> ParsedResponse {
    ParsedResponse {
        outcome: ProviderOutcome::Failure(Failure::new(kind, false)),
        response_id: None,
        returned_model: None,
        usage: None,
    }
}

fn failed_with_metadata(
    kind: FailureKind,
    response_id: String,
    returned_model: String,
    usage: Option<Usage>,
) -> ParsedResponse {
    ParsedResponse {
        outcome: ProviderOutcome::Failure(Failure::new(kind, false)),
        response_id: Some(response_id),
        returned_model: Some(returned_model),
        usage,
    }
}

fn required_safe_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
        })
        .map(str::to_owned)
}

fn parse_usage(value: Option<&Value>) -> Option<Usage> {
    let object = value?.as_object()?;
    let input_tokens = object.get("input_tokens")?.as_u64()?;
    let output_tokens = object.get("output_tokens")?.as_u64()?;
    let total_tokens = object.get("total_tokens")?.as_u64()?;
    let input_details = object
        .get("input_tokens_details")
        .and_then(Value::as_object);
    let output_details = object
        .get("output_tokens_details")
        .and_then(Value::as_object);
    let usage = Usage {
        input_tokens,
        cached_input_tokens: input_details
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_write_tokens: input_details
            .and_then(|details| {
                details
                    .get("cache_write_tokens")
                    .or_else(|| details.get("cache_creation_tokens"))
            })
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens,
        reasoning_tokens: output_details
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        total_tokens,
    };
    usage.validate().ok().map(|_| usage)
}

fn validate_receipt_schema(value: &Value) -> bool {
    let Some(object) = exact_object(
        value,
        &["merchant", "purchase_date", "currency", "line_items"],
    ) else {
        return false;
    };
    if !valid_evidence_string(object.get("merchant"), 160)
        || !valid_evidence_string(object.get("purchase_date"), 10)
        || !valid_evidence_string(object.get("currency"), 3)
    {
        return false;
    }
    if object
        .get("purchase_date")
        .and_then(|value| value.get("value"))
        .is_some_and(|value| {
            !value.is_null() && value.as_str().is_none_or(|date| !valid_date_shape(date))
        })
    {
        return false;
    }
    if object
        .get("currency")
        .and_then(|value| value.get("value"))
        .is_some_and(|value| {
            !value.is_null()
                && value.as_str().is_none_or(|currency| {
                    currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
                })
        })
    {
        return false;
    }
    let Some(lines) = object.get("line_items").and_then(Value::as_array) else {
        return false;
    };
    if lines.len() > 100 {
        return false;
    }
    lines.iter().all(|line| {
        let Some(line) = exact_object(
            line,
            &[
                "description",
                "brand",
                "category",
                "color",
                "size",
                "quantity",
                "unit_price_minor",
            ],
        ) else {
            return false;
        };
        valid_evidence_string(line.get("description"), 256)
            && valid_evidence_string(line.get("brand"), 120)
            && valid_evidence_string(line.get("category"), 80)
            && valid_evidence_string(line.get("color"), 80)
            && valid_evidence_string(line.get("size"), 48)
            && valid_evidence_integer(line.get("quantity"), 10_000)
            && valid_evidence_integer(line.get("unit_price_minor"), 100_000_000)
    })
}

fn exact_object<'a>(value: &'a Value, required_keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    if object.len() != required_keys.len()
        || !required_keys.iter().all(|key| object.contains_key(*key))
    {
        return None;
    }
    Some(object)
}

fn valid_evidence_string(value: Option<&Value>, max_length: usize) -> bool {
    let Some(object) = value.and_then(|value| exact_object(value, &["value", "source_refs"]))
    else {
        return false;
    };
    let valid_value = object.get("value").is_some_and(|value| {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|text| text.chars().count() <= max_length)
    });
    valid_value && valid_source_ref_array(object.get("source_refs"))
}

fn valid_evidence_integer(value: Option<&Value>, maximum: u64) -> bool {
    let Some(object) = value.and_then(|value| exact_object(value, &["value", "source_refs"]))
    else {
        return false;
    };
    let valid_value = object.get("value").is_some_and(|value| {
        value.is_null() || value.as_u64().is_some_and(|number| number <= maximum)
    });
    valid_value && valid_source_ref_array(object.get("source_refs"))
}

fn valid_source_ref_array(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|refs| {
        refs.len() <= 8
            && refs.iter().all(|reference| {
                reference.as_str().is_some_and(|reference| {
                    !reference.is_empty()
                        && reference.len() <= 128
                        && reference.is_ascii()
                        && !reference.bytes().any(|byte| byte.is_ascii_control())
                })
            })
    })
}

fn valid_date_shape(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn valid_source_references(
    observation: &ReceiptObservationV1,
    submitted: &BTreeSet<String>,
) -> bool {
    let mut strings = vec![
        &observation.merchant,
        &observation.purchase_date,
        &observation.currency,
    ];
    let mut integers = Vec::new();
    for line in &observation.line_items {
        strings.extend([
            &line.description,
            &line.brand,
            &line.category,
            &line.color,
            &line.size,
        ]);
        integers.extend([&line.quantity, &line.unit_price_minor]);
    }
    strings
        .into_iter()
        .all(|field| valid_field_sources(field.value.is_some(), &field.source_refs, submitted))
        && integers
            .into_iter()
            .all(|field| valid_field_sources(field.value.is_some(), &field.source_refs, submitted))
}

fn valid_field_sources(known: bool, references: &[String], submitted: &BTreeSet<String>) -> bool {
    if known == references.is_empty() {
        return false;
    }
    let unique = references.iter().collect::<BTreeSet<_>>();
    unique.len() == references.len()
        && references
            .iter()
            .all(|reference| submitted.contains(reference))
}

#[allow(dead_code)]
fn _typed_contract(
    _string: EvidenceString,
    _integer: EvidenceInteger,
    _line: GarmentLineObservation,
) {
}

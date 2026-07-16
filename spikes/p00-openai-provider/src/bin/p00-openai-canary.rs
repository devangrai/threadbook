use p00_openai_provider::{
    ApprovalDecision, ApprovalReceipt, ApprovedExtractionRequest, CropDetail, CropInput, CropMime,
    PreparedEvidence, ProjectRetention, ProviderConfig, ProviderExchange, ProviderOutcome,
    RateCard, ReceiptEvidenceProvider, ReceiptLineTextInput, ReceiptTextInput, ReqwestTransport,
    RetentionMode, SanitizedCrop, SanitizedReceiptText, TransmittedFields, Usage,
};
use serde::Serialize;
use std::process::ExitCode;

const TEXT_SENTINEL: &str = "P00_LIVE_TEXT_SENTINEL_ALPHA";
const CROP_SENTINEL: &str = "P00_LIVE_CROP_SENTINEL_BETA";

#[derive(Debug)]
enum CanaryError {
    MissingInput,
    InvalidInput,
    ProviderFailure,
    MissingProviderMetadata,
    SentinelLeak,
}

#[derive(Serialize)]
struct LiveRecord {
    scenario: &'static str,
    nonce: String,
    status: &'static str,
    transmitted: TransmittedFields,
    retention_mode: String,
    retention_provenance: String,
    client_request_id: String,
    provider_request_id: String,
    response_id: String,
    returned_model: String,
    latency_millis: u64,
    usage: Usage,
    estimated_micro_usd: u64,
    rate_card_id: String,
    calculation_revision: String,
    service_tier: String,
    region: String,
    service_tier_uplift_bps: u32,
    region_uplift_bps: u32,
    model_revision: String,
    store_false: bool,
    schema_or_refusal: &'static str,
    no_sentinel_leaks: bool,
    synthetic_nonpersonal_data: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(records) => {
            for record in records {
                println!(
                    "P00_OPENAI_EVIDENCE {}",
                    serde_json::to_string(&record)
                        .expect("validated canary evidence record must serialize")
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("p00-openai-canary failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<[LiveRecord; 2], CanaryError> {
    require_present("OPENAI_API_KEY")?;
    let nonce = evidence_nonce()?;
    let retention_mode = parse_retention_mode(
        &std::env::var("P00_OPENAI_RETENTION_MODE").map_err(|_| CanaryError::MissingInput)?,
    )?;
    let retention_provenance =
        std::env::var("P00_OPENAI_RETENTION_PROVENANCE").map_err(|_| CanaryError::MissingInput)?;
    let rate_card_json =
        std::env::var("P00_OPENAI_RATE_CARD_JSON").map_err(|_| CanaryError::MissingInput)?;
    let rate_card: RateCard =
        serde_json::from_str(&rate_card_json).map_err(|_| CanaryError::InvalidInput)?;
    let today = utc_date_now().ok_or(CanaryError::InvalidInput)?;
    let retention = ProjectRetention::new(retention_mode, retention_provenance)
        .map_err(|_| CanaryError::InvalidInput)?;
    let config =
        ProviderConfig::new(retention, rate_card, &today).map_err(|_| CanaryError::InvalidInput)?;
    let transport = ReqwestTransport::from_env().map_err(|_| CanaryError::InvalidInput)?;
    let provider = ReceiptEvidenceProvider::new(transport, config);

    let text_evidence = PreparedEvidence::new(
        Some(
            SanitizedReceiptText::sanitize(ReceiptTextInput {
                merchant: Some("Synthetic Outfit Store".to_owned()),
                purchase_date: Some(today),
                currency: Some("USD".to_owned()),
                line_items: vec![ReceiptLineTextInput {
                    description: Some(format!("Synthetic green shirt {TEXT_SENTINEL}")),
                    brand: Some("Test Loom".to_owned()),
                    category: Some("shirt".to_owned()),
                    color: Some("green".to_owned()),
                    size: Some("M".to_owned()),
                    quantity: Some(1),
                    unit_price_minor: Some(2_500),
                }],
            })
            .map_err(|_| CanaryError::InvalidInput)?,
        ),
        vec![],
    )
    .map_err(|_| CanaryError::InvalidInput)?;

    let crop = SanitizedCrop::sanitize(CropInput {
        source_id: format!("crop.synthetic-shirt-{CROP_SENTINEL}"),
        bytes: p00_openai_provider::synthetic::face_free_garment_crop_png(),
        mime: CropMime::Png,
        detail: CropDetail::Low,
        face_free: true,
        surroundings_minimized: true,
    })
    .map_err(|_| CanaryError::InvalidInput)?;
    let crop_evidence =
        PreparedEvidence::new(None, vec![crop]).map_err(|_| CanaryError::InvalidInput)?;

    let text_exchange = execute(&provider, "p00-live-text-canary", text_evidence)?;
    let crop_exchange = execute(&provider, "p00-live-crop-canary", crop_evidence)?;
    let text_record = live_record("live_text_canary", &nonce, &text_exchange)?;
    let crop_record = live_record("live_crop_canary", &nonce, &crop_exchange)?;

    let serialized_audits = serde_json::to_string(&[&text_exchange.audit, &crop_exchange.audit])
        .map_err(|_| CanaryError::InvalidInput)?;
    let serialized_records = serde_json::to_string(&[&text_record, &crop_record])
        .map_err(|_| CanaryError::InvalidInput)?;
    for sentinel in [TEXT_SENTINEL, CROP_SENTINEL] {
        if serialized_audits.contains(sentinel) || serialized_records.contains(sentinel) {
            return Err(CanaryError::SentinelLeak);
        }
    }
    Ok([text_record, crop_record])
}

fn execute(
    provider: &ReceiptEvidenceProvider<ReqwestTransport>,
    operation_id: &str,
    evidence: PreparedEvidence,
) -> Result<ProviderExchange, CanaryError> {
    let preview = provider
        .disclosure_preview(&evidence)
        .map_err(|_| CanaryError::InvalidInput)?;
    let approval = ApprovalReceipt::confirm(preview.preview_hash(), ApprovalDecision::Affirmed)
        .map_err(|_| CanaryError::InvalidInput)?;
    let exchange = provider.extract(ApprovedExtractionRequest::new(
        operation_id,
        evidence,
        approval,
    ));
    if !matches!(
        exchange.outcome,
        ProviderOutcome::Success(_) | ProviderOutcome::Refusal(_)
    ) {
        return Err(CanaryError::ProviderFailure);
    }
    Ok(exchange)
}

fn live_record(
    scenario: &'static str,
    nonce: &str,
    exchange: &ProviderExchange,
) -> Result<LiveRecord, CanaryError> {
    let client_request_id = exchange
        .audit
        .client_request_id
        .value
        .clone()
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let provider_request_id = exchange
        .audit
        .provider_request_id
        .value
        .clone()
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let response_id = exchange
        .audit
        .response_id
        .value
        .clone()
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let returned_model = exchange
        .audit
        .returned_model
        .clone()
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let usage = exchange
        .audit
        .usage
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let cost = exchange
        .audit
        .cost
        .as_ref()
        .ok_or(CanaryError::MissingProviderMetadata)?;
    let schema_or_refusal = match exchange.outcome {
        ProviderOutcome::Success(_) => "schema_valid",
        ProviderOutcome::Refusal(_) => "explicit_refusal",
        ProviderOutcome::Failure(_) => return Err(CanaryError::ProviderFailure),
    };
    Ok(LiveRecord {
        scenario,
        nonce: nonce.to_owned(),
        status: "pass",
        transmitted: exchange.audit.transmitted.clone(),
        retention_mode: exchange.audit.retention.mode.as_str().to_owned(),
        retention_provenance: exchange.audit.retention.provenance.clone(),
        client_request_id,
        provider_request_id,
        response_id,
        returned_model,
        latency_millis: exchange.audit.latency_millis,
        usage,
        estimated_micro_usd: cost.estimated_micro_usd,
        rate_card_id: cost.rate_card_id.clone(),
        calculation_revision: cost.calculation_revision.clone(),
        service_tier: cost.service_tier.clone(),
        region: cost.region.clone(),
        service_tier_uplift_bps: cost.service_tier_uplift_bps,
        region_uplift_bps: cost.region_uplift_bps,
        model_revision: cost.model_revision.clone(),
        store_false: !exchange.audit.store,
        schema_or_refusal,
        no_sentinel_leaks: true,
        synthetic_nonpersonal_data: true,
    })
}

fn evidence_nonce() -> Result<String, CanaryError> {
    let nonce =
        std::env::var("P00_OPENAI_EVIDENCE_NONCE").map_err(|_| CanaryError::MissingInput)?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanaryError::InvalidInput);
    }
    Ok(nonce)
}

fn require_present(name: &str) -> Result<(), CanaryError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|_| ())
        .ok_or(CanaryError::MissingInput)
}

fn parse_retention_mode(value: &str) -> Result<RetentionMode, CanaryError> {
    match value {
        "unknown" => Ok(RetentionMode::Unknown),
        "default" => Ok(RetentionMode::Default),
        "MAM" => Ok(RetentionMode::Mam),
        "ZDR" => Ok(RetentionMode::Zdr),
        _ => Err(CanaryError::InvalidInput),
    }
}

fn utc_date_now() -> Option<String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let days = i64::try_from(seconds / 86_400).ok()?;
    let (year, month, day) = civil_from_days(days);
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

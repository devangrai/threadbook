use crate::{
    Database, MacOsKeychain, OpenAiImageEditsFailureKind, OpenAiImageEditsHttpTransport,
    OpenAiImageEditsRequest, PlatformError, PlatformResult,
};
use serde_json::json;
use wardrobe_core::{TryOnAssetRoleV1, TryOnFailureCodeV1};

pub struct ProductionTryOnRenderer {
    database: Database,
    transport: OpenAiImageEditsHttpTransport,
}

impl ProductionTryOnRenderer {
    pub fn production(database: Database) -> PlatformResult<Self> {
        let transport = OpenAiImageEditsHttpTransport::production()
            .map_err(|_| PlatformError::Unsupported("try_on_provider_configuration"))?;
        Ok(Self {
            database,
            transport,
        })
    }

    pub async fn run_once(&self, owner: &str, now_ms: i64) -> PlatformResult<bool> {
        let Some(claim) = self
            .database
            .claim_try_on_job(owner, now_ms, 4 * 60 * 1_000)?
        else {
            return Ok(false);
        };
        let locator = match self.database.authorize_try_on_transport(&claim, now_ms) {
            Ok(locator) => locator,
            Err(error) => {
                self.database.fail_try_on_job(
                    &claim,
                    TryOnFailureCodeV1::CredentialUnavailable,
                    now_ms,
                )?;
                let _ = error;
                return Ok(true);
            }
        };
        let secret = match MacOsKeychain.get_exact(&locator) {
            Ok(secret) => secret,
            Err(_) => {
                self.database.fail_try_on_job(
                    &claim,
                    TryOnFailureCodeV1::CredentialUnavailable,
                    now_ms,
                )?;
                return Ok(true);
            }
        };
        let portrait = claim
            .assets
            .first()
            .filter(|asset| asset.ordinal == 0 && asset.role == TryOnAssetRoleV1::Portrait)
            .ok_or(PlatformError::Corrupt("try_on_portrait_order"))?;
        let garments = claim
            .assets
            .iter()
            .skip(1)
            .map(|asset| {
                if asset.role != TryOnAssetRoleV1::Garment {
                    return Err(PlatformError::Corrupt("try_on_garment_order"));
                }
                Ok(asset.png_bytes.as_slice())
            })
            .collect::<PlatformResult<Vec<_>>>()?;
        self.database
            .mark_try_on_transport_started(&claim, now_ms)?;
        let result = self
            .transport
            .generate(
                &secret,
                OpenAiImageEditsRequest {
                    portrait_png: &portrait.png_bytes,
                    garment_pngs: &garments,
                },
            )
            .await;
        match result {
            Ok(output) => {
                let audit = json!({
                    "provider_request_id": output.metadata.request_id,
                    "status": output.metadata.status,
                    "latency_ms": output.metadata.latency_ms,
                    "response_bytes": output.metadata.response_bytes,
                    "transport_started_at_ms": now_ms,
                    "automatic_retry": false
                });
                let audit_json = serde_json::to_string(&audit)?;
                let output_hash =
                    self.database
                        .begin_try_on_output(&claim, &output.png, &audit_json, now_ms)?;
                self.database
                    .finalize_try_on_output(&claim, &output.png, &output_hash, now_ms)?;
            }
            Err(error) => {
                if error.failed_before_send() {
                    self.database
                        .clear_try_on_transport_started(&claim, now_ms)?;
                }
                self.database
                    .fail_try_on_job(&claim, map_failure(error.kind), now_ms)?;
            }
        }
        Ok(true)
    }
}

fn map_failure(value: OpenAiImageEditsFailureKind) -> TryOnFailureCodeV1 {
    match value {
        OpenAiImageEditsFailureKind::ModerationBlocked => TryOnFailureCodeV1::ModerationBlocked,
        OpenAiImageEditsFailureKind::RateLimited => TryOnFailureCodeV1::RateLimited,
        OpenAiImageEditsFailureKind::ProviderFailure => TryOnFailureCodeV1::ProviderFailure,
        OpenAiImageEditsFailureKind::ProviderUnavailable => TryOnFailureCodeV1::ProviderUnavailable,
        OpenAiImageEditsFailureKind::OutcomeUnknown => TryOnFailureCodeV1::OutcomeUnknown,
        OpenAiImageEditsFailureKind::Authentication => TryOnFailureCodeV1::Authentication,
        OpenAiImageEditsFailureKind::PermissionDenied => TryOnFailureCodeV1::PermissionDenied,
        OpenAiImageEditsFailureKind::RequestRejected => TryOnFailureCodeV1::RequestRejected,
        OpenAiImageEditsFailureKind::ProviderProtocol => TryOnFailureCodeV1::ProviderProtocol,
    }
}

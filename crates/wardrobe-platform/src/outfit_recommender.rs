use crate::{
    Database, MacOsKeychain, OpenAiOutfitRecommendationProvider, OpenAiResponsesHttpError,
    OutfitRecommendationRequestPlan, PlatformError, PlatformResult,
};
use wardrobe_core::{
    CredentialPort, OutfitRecommendationFailureCodeV1, OutfitRecommendationOutcomeV1,
    PreviewOutfitRecommendationV1Request, PreviewOutfitRecommendationV1Response,
    RequestOutfitRecommendationV1Request, RequestOutfitRecommendationV1Response, SecretString,
    SCHEMA_VERSION_V1,
};

#[derive(Clone)]
pub struct ProductionOutfitRecommender {
    database: Database,
    keychain: MacOsKeychain,
    provider: OpenAiOutfitRecommendationProvider,
}

impl ProductionOutfitRecommender {
    pub fn production(database: Database) -> Result<Self, OpenAiResponsesHttpError> {
        Ok(Self {
            database,
            keychain: MacOsKeychain,
            provider: OpenAiOutfitRecommendationProvider::production()?,
        })
    }

    pub fn new(
        database: Database,
        keychain: MacOsKeychain,
        provider: OpenAiOutfitRecommendationProvider,
    ) -> Self {
        Self {
            database,
            keychain,
            provider,
        }
    }

    pub fn preview(
        &self,
        request: &PreviewOutfitRecommendationV1Request,
        now_ms: i64,
    ) -> PlatformResult<PreviewOutfitRecommendationV1Response> {
        self.database.preview_outfit_recommendation(request, now_ms)
    }

    pub fn request(
        &self,
        request: &RequestOutfitRecommendationV1Request,
        now_ms: i64,
    ) -> PlatformResult<RequestOutfitRecommendationV1Response> {
        coordinate_request(
            &self.database,
            request,
            now_ms,
            |locator| self.keychain.get(locator).ok(),
            |api_key, request, snapshot| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PlatformError::Unsupported("recommendation_runtime"))?;
                Ok(runtime.block_on(self.provider.recommend(api_key, request, snapshot)))
            },
        )
    }
}

fn coordinate_request<GetCredential, Recommend>(
    database: &Database,
    request: &RequestOutfitRecommendationV1Request,
    now_ms: i64,
    get_credential: GetCredential,
    recommend: Recommend,
) -> PlatformResult<RequestOutfitRecommendationV1Response>
where
    GetCredential: FnOnce(&wardrobe_core::CredentialLocator) -> Option<SecretString>,
    Recommend: FnOnce(
        &SecretString,
        &RequestOutfitRecommendationV1Request,
        &crate::OutfitRecommendationToolSnapshot,
    ) -> PlatformResult<RequestOutfitRecommendationV1Response>,
{
    let reservation = match database.reserve_outfit_recommendation(request, now_ms)? {
        OutfitRecommendationRequestPlan::Replay(response) => return Ok(response),
        OutfitRecommendationRequestPlan::Execute(reservation) => reservation,
    };

    let api_key = match get_credential(&reservation.credential_locator) {
        Some(value) => value,
        None => {
            return database.finalize_outfit_recommendation(
                &reservation.attempt_id,
                credential_unavailable(request),
                now_ms,
            )
        }
    };

    if !database.authorize_outfit_recommendation_transport_start(&reservation.attempt_id, now_ms)? {
        drop(api_key);
        return database.finalize_outfit_recommendation(
            &reservation.attempt_id,
            credential_unavailable(request),
            now_ms,
        );
    }

    let response = recommend(&api_key, &reservation.request, &reservation.snapshot)?;
    drop(api_key);
    database.finalize_outfit_recommendation(&reservation.attempt_id, response, now_ms)
}

fn credential_unavailable(
    request: &RequestOutfitRecommendationV1Request,
) -> RequestOutfitRecommendationV1Response {
    RequestOutfitRecommendationV1Response {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request.request_id,
        outcome: OutfitRecommendationOutcomeV1::Failed {
            code: OutfitRecommendationFailureCodeV1::CredentialUnavailable,
            retryable: false,
            audit: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateAppPaths;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    };
    use std::thread;
    use std::time::Duration;
    use uuid::Uuid;
    use wardrobe_core::{
        CredentialId, DatabasePort, OpenAiRetentionDeclarationV1, OpenAiRetentionModeV1,
        OutfitRecommendationConstraintsV1, OutfitRecommendationEnvelopeV1, RequestId,
    };

    const CREDENTIAL_ID: &str = "11111111-1111-4111-8111-111111111111";
    const WAIT: Duration = Duration::from_secs(5);

    fn setup() -> (
        tempfile::TempDir,
        Database,
        RequestOutfitRecommendationV1Request,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (
                    '44444444-4444-4444-8444-444444444444',
                    ?1,
                    '55555555-5555-4555-8555-555555555555',
                    'open_ai', 'OpenAI', 'active', 1, 1
                 )",
                [CREDENTIAL_ID],
            )
            .unwrap();
        let envelope = OutfitRecommendationEnvelopeV1 {
            prompt: "A casual outfit".to_owned(),
            credential_id: credential_id(),
            constraints: OutfitRecommendationConstraintsV1 {
                occasion: None,
                temperature_c: None,
                precipitation: None,
            },
            excluded_item_ids: Vec::new(),
            requested_proposal_count: 1,
            expected_catalog_revision: 0,
            expected_outfit_revision: 0,
            retention: OpenAiRetentionDeclarationV1 {
                mode: OpenAiRetentionModeV1::Unknown,
                provenance: "user_declared".to_owned(),
            },
        };
        let preview = database
            .preview_outfit_recommendation(
                &PreviewOutfitRecommendationV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: RequestId::new_v4(),
                    envelope: envelope.clone(),
                },
                2,
            )
            .unwrap();
        let request = RequestOutfitRecommendationV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            approval_id: preview.approval.approval_id,
            envelope,
        };
        (temporary, database, request)
    }

    fn credential_id() -> CredentialId {
        CredentialId::new(Uuid::parse_str(CREDENTIAL_ID).unwrap()).unwrap()
    }

    fn provider_failure(
        request: &RequestOutfitRecommendationV1Request,
    ) -> RequestOutfitRecommendationV1Response {
        RequestOutfitRecommendationV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            outcome: OutfitRecommendationOutcomeV1::Failed {
                code: OutfitRecommendationFailureCodeV1::ProviderFailure,
                retryable: false,
                audit: None,
            },
        }
    }

    #[test]
    fn credential_inactivated_after_secret_read_wins_before_transport_gate() {
        let (_temporary, database, request) = setup();
        let (secret_read_tx, secret_read_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let coordinator_database = database.clone();
        let coordinator_request = request.clone();
        let coordinator_calls = Arc::clone(&provider_calls);

        let coordinator = thread::spawn(move || {
            coordinate_request(
                &coordinator_database,
                &coordinator_request,
                3,
                move |_| {
                    let secret = SecretString::new("test-api-key".to_owned());
                    secret_read_tx.send(()).unwrap();
                    deleted_rx.recv_timeout(WAIT).unwrap();
                    Some(secret)
                },
                move |_, request, _| {
                    coordinator_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(provider_failure(request))
                },
            )
        });

        secret_read_rx.recv_timeout(WAIT).unwrap();
        database
            .prepare_credential_delete(RequestId::new_v4(), credential_id())
            .unwrap();
        deleted_tx.send(()).unwrap();

        let response = coordinator.join().unwrap().unwrap();
        assert!(matches!(
            response.outcome,
            OutfitRecommendationOutcomeV1::Failed {
                code: OutfitRecommendationFailureCodeV1::CredentialUnavailable,
                retryable: false,
                ..
            }
        ));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        let marker_count: i64 = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM outfit_recommendation_attempts
                 WHERE transport_started_at_ms IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(0, marker_count);
    }

    #[test]
    fn credential_inactivated_after_transport_gate_does_not_revoke_dispatch() {
        let (_temporary, database, request) = setup();
        let (provider_started_tx, provider_started_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let coordinator_database = database.clone();
        let coordinator_request = request.clone();
        let coordinator_calls = Arc::clone(&provider_calls);

        let coordinator = thread::spawn(move || {
            coordinate_request(
                &coordinator_database,
                &coordinator_request,
                3,
                |_| Some(SecretString::new("test-api-key".to_owned())),
                move |_, request, _| {
                    coordinator_calls.fetch_add(1, Ordering::SeqCst);
                    provider_started_tx.send(()).unwrap();
                    deleted_rx.recv_timeout(WAIT).unwrap();
                    Ok(provider_failure(request))
                },
            )
        });

        provider_started_rx.recv_timeout(WAIT).unwrap();
        database
            .prepare_credential_delete(RequestId::new_v4(), credential_id())
            .unwrap();
        deleted_tx.send(()).unwrap();

        let response = coordinator.join().unwrap().unwrap();
        assert!(matches!(
            response.outcome,
            OutfitRecommendationOutcomeV1::Failed {
                code: OutfitRecommendationFailureCodeV1::ProviderFailure,
                ..
            }
        ));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        let transport_started_at_ms: i64 = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT transport_started_at_ms FROM outfit_recommendation_attempts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(3, transport_started_at_ms);
    }
}

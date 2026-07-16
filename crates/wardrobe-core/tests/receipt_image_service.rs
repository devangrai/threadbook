use std::future::{ready, Future};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use wardrobe_core::*;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

#[derive(Clone)]
struct Downloader {
    calls: Arc<Mutex<usize>>,
    result: Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1>,
}

impl ReceiptImageDownloader for Downloader {
    fn download(
        &self,
        _normalized_url: String,
        _approved_display_host: String,
    ) -> impl Future<Output = Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1>> + Send
    {
        *self.calls.lock().unwrap() += 1;
        ready(self.result.clone())
    }
}

struct Database {
    candidate: ReceiptImageCandidateSummaryV1,
    plan: Mutex<ReceiptImageAttemptPlanV1>,
}

impl ReceiptPort for Database {
    fn list_receipts(
        &self,
        _request: &ListReceiptsV1Request,
    ) -> ReceiptPortResult<ListReceiptsV1Response> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn prepare_receipt_analysis(
        &self,
        _request: &AnalyzeReceiptV1Request,
    ) -> ReceiptPortResult<ReceiptAnalysisPlanV1> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn commit_receipt_analysis(
        &self,
        _request: &AnalyzeReceiptV1Request,
        _parsed: &ParsedReceiptEvidenceV1,
        _envelope: &ReceiptExtractionEnvelopeV1,
        _preserved_review_head: Option<&ReceiptReviewHeadV1>,
    ) -> ReceiptPortResult<AnalyzeReceiptV1Response> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn record_receipt_analysis_failure(
        &self,
        _request: &AnalyzeReceiptV1Request,
        _parsed: &ParsedReceiptEvidenceV1,
        _failure: ReceiptAnalysisFailureV1,
    ) -> ReceiptPortResult<ReceiptAnalysisFailureV1> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn review_receipt_and_append_decision(
        &self,
        _request: &ReviewReceiptV1Request,
    ) -> ReceiptPortResult<ReviewReceiptV1Response> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn list_receipt_image_candidates(
        &self,
        request: &ListReceiptImageCandidatesV1Request,
    ) -> ReceiptPortResult<ListReceiptImageCandidatesV1Response> {
        Ok(ListReceiptImageCandidatesV1Response {
            schema_version: 1,
            request_id: request.request_id,
            source_id: request.source_id,
            candidates: vec![self.candidate.clone()],
            omitted_count: 0,
        })
    }

    fn prepare_image_attempt(
        &self,
        _request: &ApproveAndFetchReceiptImageV1Request,
    ) -> ReceiptPortResult<ReceiptImageAttemptPlanV1> {
        Ok(self.plan.lock().unwrap().clone())
    }

    fn finalize_image_attempt(
        &self,
        request: &ApproveAndFetchReceiptImageV1Request,
        attempt_id: ReceiptImageAttemptId,
        _download_token: &str,
        result: Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1>,
    ) -> ReceiptPortResult<ApproveAndFetchReceiptImageV1Response> {
        let failure_code = result.err();
        Ok(ApproveAndFetchReceiptImageV1Response {
            schema_version: 1,
            request_id: request.request_id,
            candidate_id: request.candidate_id,
            attempt_id,
            outcome: ReceiptImageAttemptOutcomeV1::TransportFailed,
            failure_code,
            artifact: None,
            replay_status: ReplayStatusV1::Created,
        })
    }
}

fn fixture() -> (
    Database,
    Downloader,
    ListReceiptImageCandidatesV1Request,
    ApproveAndFetchReceiptImageV1Request,
) {
    let source_id = SourceId::new_v4();
    let candidate = ReceiptImageCandidateSummaryV1 {
        candidate_id: ReceiptImageCandidateId::new_v4(),
        source_id,
        display_host: "images.example.test".to_owned(),
        candidate_url_sha256: Sha256Digest::from_bytes(b"candidate"),
        eligibility: ReceiptImageCandidateEligibilityV1::Eligible,
        latest_attempt: None,
    };
    let attempt_id = ReceiptImageAttemptId::new_v4();
    let database = Database {
        candidate: candidate.clone(),
        plan: Mutex::new(ReceiptImageAttemptPlanV1::Download {
            attempt_id,
            download_token: "one-use-token".to_owned(),
            normalized_url: "https://images.example.test/item.png".to_owned(),
            approved_display_host: candidate.display_host.clone(),
        }),
    };
    let calls = Arc::new(Mutex::new(0));
    let downloader = Downloader {
        calls,
        result: Err(ReceiptImageFailureCodeV1::TransportFailed),
    };
    let list = ListReceiptImageCandidatesV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id,
    };
    let approve = ApproveAndFetchReceiptImageV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        candidate_id: candidate.candidate_id,
        approved_display_host: candidate.display_host,
        candidate_url_sha256: candidate.candidate_url_sha256,
        prior_attempt_id: None,
    };
    (database, downloader, list, approve)
}

#[test]
fn service_lists_inert_candidates_and_fetches_only_after_a_download_plan() {
    let (database, downloader, list, approve) = fixture();
    let calls = downloader.calls.clone();
    let service =
        ApplicationService::new(database, (), ()).with_receipt_image_downloader(downloader);

    let listed = service.list_receipt_image_candidates_v1(list).unwrap();
    assert_eq!(listed.candidates.len(), 1);
    assert_eq!(*calls.lock().unwrap(), 0);

    let response = block_on(service.approve_and_fetch_receipt_image_v1(approve)).unwrap();
    assert_eq!(
        response.outcome,
        ReceiptImageAttemptOutcomeV1::TransportFailed
    );
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn exact_replay_never_invokes_the_downloader() {
    let (database, downloader, _list, approve) = fixture();
    let calls = downloader.calls.clone();
    let replay = ApproveAndFetchReceiptImageV1Response {
        schema_version: 1,
        request_id: approve.request_id,
        candidate_id: approve.candidate_id,
        attempt_id: ReceiptImageAttemptId::new_v4(),
        outcome: ReceiptImageAttemptOutcomeV1::Ambiguous,
        failure_code: Some(ReceiptImageFailureCodeV1::DeadlineExceeded),
        artifact: None,
        replay_status: ReplayStatusV1::Replayed,
    };
    *database.plan.lock().unwrap() = ReceiptImageAttemptPlanV1::Replay(replay);
    let service =
        ApplicationService::new(database, (), ()).with_receipt_image_downloader(downloader);

    let response = block_on(service.approve_and_fetch_receipt_image_v1(approve)).unwrap();
    assert_eq!(response.replay_status, ReplayStatusV1::Replayed);
    assert_eq!(*calls.lock().unwrap(), 0);
}

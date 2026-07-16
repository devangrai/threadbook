use crate::contracts::{
    AvailabilityReason, CommitFault, CommitStats, HistoryId, SourceEffect, SourceIdentity,
    StoreError, SyncKey, SyncStore,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ProfileHistory,
    ListMessages,
    GetMessage,
    ListHistory,
    Commit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticError {
    Authentication,
    Permission,
    Quota,
    RateLimited,
    Transient,
    MalformedRequest,
    MessageNotFound,
    Cancelled,
    BoundExceeded,
    CompareAndSwap,
    Invariant,
    Store,
    Script,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayError {
    CursorExpired,
    CursorInvalid,
    Authentication,
    Permission,
    Quota,
    RateLimited,
    Transient,
    MalformedRequest,
    MessageNotFound,
    Cancelled,
    ReconciliationRestart,
    UnexpectedScript,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gmail gateway error: {self:?}")
    }
}

impl Error for GatewayError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmailMessage {
    pub id: String,
    pub history_id: String,
    pub thread_id: String,
    pub rfc_message_id: String,
    pub evidence_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagePage {
    pub message_ids: Vec<String>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryEventKind {
    Upsert,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEvent {
    pub history_id: String,
    pub message_id: String,
    pub kind: HistoryEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub events: Vec<HistoryEvent>,
    pub next_page_token: Option<String>,
    pub mailbox_history_id: String,
}

pub trait GmailGateway {
    fn profile_history_id(&mut self) -> Result<String, GatewayError>;
    fn list_messages(
        &mut self,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<MessagePage, GatewayError>;
    fn get_message(&mut self, message_id: &str) -> Result<GmailMessage, GatewayError>;
    fn list_history(
        &mut self,
        start_history_id: &str,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<HistoryPage, GatewayError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    Initial,
    ExpiredCursor,
    InvalidCursor,
    MalformedCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SyncLimits {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_unique_messages: usize,
    pub max_gateway_calls: usize,
    pub max_scan_attempts: usize,
}

impl SyncLimits {
    pub const EVALUATOR: Self = Self {
        page_size: 2,
        max_pages: 3,
        max_unique_messages: 5,
        max_gateway_calls: 16,
        max_scan_attempts: 2,
    };

    fn valid(self) -> bool {
        self.page_size > 0
            && self.max_pages > 0
            && self.max_unique_messages > 0
            && self.max_gateway_calls > 0
            && self.max_scan_attempts > 0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub operation: Option<Operation>,
    pub error: Option<DiagnosticError>,
    pub fallback: Option<FallbackReason>,
    pub pages: usize,
    pub unique_messages: usize,
    pub gateway_calls: usize,
    pub scan_attempts: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncReport {
    pub cursor: String,
    pub diagnostic: Diagnostic,
    pub commit: CommitStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    Incremental(SyncReport),
    Reconciled(SyncReport),
}

impl SyncOutcome {
    pub fn report(&self) -> &SyncReport {
        match self {
            Self::Incremental(report) | Self::Reconciled(report) => report,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncErrorKind {
    IncompleteBoundExceeded,
    Authentication,
    Permission,
    Quota,
    RateLimited,
    Transient,
    MalformedRequest,
    MessageNotFound,
    Cancelled,
    CompareAndSwap,
    Invariant,
    Store,
    UnexpectedScript,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncError {
    pub kind: SyncErrorKind,
    pub diagnostic: Diagnostic,
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gmail sync error: {:?}", self.kind)
    }
}

impl Error for SyncError {}

pub struct SyncCoordinator<'a, G, S> {
    gateway: &'a mut G,
    store: &'a S,
    limits: SyncLimits,
}

impl<'a, G: GmailGateway, S: SyncStore> SyncCoordinator<'a, G, S> {
    pub fn new(gateway: &'a mut G, store: &'a S, limits: SyncLimits) -> Self {
        Self {
            gateway,
            store,
            limits,
        }
    }

    pub fn sync(&mut self, key: &SyncKey) -> Result<SyncOutcome, SyncError> {
        self.sync_with_fault(key, CommitFault::None)
    }

    pub fn sync_with_fault(
        &mut self,
        key: &SyncKey,
        fault: CommitFault,
    ) -> Result<SyncOutcome, SyncError> {
        let mut diagnostic = Diagnostic::default();
        if !key.valid() || !self.limits.valid() {
            return Err(self.error(
                SyncErrorKind::Invariant,
                DiagnosticError::Invariant,
                &diagnostic,
            ));
        }
        let committed = self
            .store
            .checkpoint(key)
            .map_err(|error| self.store_error(error, Operation::Commit, diagnostic.clone()))?;

        let Some(raw_cursor) = committed.clone() else {
            return self.reconcile(key, None, FallbackReason::Initial, fault, diagnostic);
        };
        let cursor = match HistoryId::parse(raw_cursor.clone()) {
            Ok(cursor) => cursor,
            Err(_) => {
                return self.reconcile(
                    key,
                    Some(raw_cursor.as_str()),
                    FallbackReason::MalformedCursor,
                    fault,
                    diagnostic,
                )
            }
        };

        let mut token = None;
        let mut effects = Vec::new();
        let mut seen_revisions = HashMap::new();
        let mut next_cursor = cursor.clone();
        loop {
            diagnostic.operation = Some(Operation::ListHistory);
            self.consume_call(&mut diagnostic)?;
            let page = match self.gateway.list_history(
                cursor.as_str(),
                token.as_deref(),
                self.limits.page_size,
            ) {
                Ok(page) => page,
                Err(GatewayError::CursorExpired) => {
                    diagnostic.fallback = Some(FallbackReason::ExpiredCursor);
                    return self.reconcile(
                        key,
                        Some(raw_cursor.as_str()),
                        FallbackReason::ExpiredCursor,
                        fault,
                        diagnostic,
                    );
                }
                Err(GatewayError::CursorInvalid) => {
                    diagnostic.fallback = Some(FallbackReason::InvalidCursor);
                    return self.reconcile(
                        key,
                        Some(raw_cursor.as_str()),
                        FallbackReason::InvalidCursor,
                        fault,
                        diagnostic,
                    );
                }
                Err(error) => return Err(self.gateway_error(error, &diagnostic)),
            };
            diagnostic.pages += 1;
            let page_cursor = self.history_id(&page.mailbox_history_id, &diagnostic)?;
            if cursor.is_after(&page_cursor) {
                return Err(self.error(
                    SyncErrorKind::Invariant,
                    DiagnosticError::Invariant,
                    &diagnostic,
                ));
            }
            next_cursor = next_cursor.max(page_cursor);
            for event in page.events {
                let revision = self.history_id(&event.history_id, &diagnostic)?;
                if !revision.is_after(&cursor) {
                    return Err(self.error(
                        SyncErrorKind::Invariant,
                        DiagnosticError::Invariant,
                        &diagnostic,
                    ));
                }
                let identity = SourceIdentity::new(key, event.message_id.clone());
                let revision_key = (event.message_id.clone(), revision.as_str().to_owned());
                if let Some(previous_kind) = seen_revisions.get(&revision_key) {
                    if *previous_kind == event.kind {
                        continue;
                    }
                    return Err(self.error(
                        SyncErrorKind::Invariant,
                        DiagnosticError::Invariant,
                        &diagnostic,
                    ));
                }
                seen_revisions.insert(revision_key, event.kind);
                match event.kind {
                    HistoryEventKind::Deleted => {
                        if self
                            .store
                            .source_id(&identity)
                            .map_err(|error| {
                                self.store_error(error, Operation::Commit, diagnostic.clone())
                            })?
                            .is_some()
                        {
                            effects.push(SourceEffect {
                                identity,
                                revision,
                                available: false,
                                reason: AvailabilityReason::HistoryDeletion,
                                evidence_fingerprint: "history-deletion".into(),
                            });
                        }
                    }
                    HistoryEventKind::Upsert => {
                        diagnostic.operation = Some(Operation::GetMessage);
                        self.consume_call(&mut diagnostic)?;
                        match self.gateway.get_message(&event.message_id) {
                            Ok(message) => effects.push(self.message_effect(
                                key,
                                &event.message_id,
                                message,
                                &diagnostic,
                            )?),
                            Err(GatewayError::MessageNotFound) => {
                                if self
                                    .store
                                    .source_id(&identity)
                                    .map_err(|error| {
                                        self.store_error(
                                            error,
                                            Operation::Commit,
                                            diagnostic.clone(),
                                        )
                                    })?
                                    .is_some()
                                {
                                    effects.push(SourceEffect {
                                        identity,
                                        revision,
                                        available: false,
                                        reason: AvailabilityReason::MessageNotFound,
                                        evidence_fingerprint: "message-not-found".into(),
                                    });
                                }
                            }
                            Err(error) => return Err(self.gateway_error(error, &diagnostic)),
                        }
                    }
                }
            }
            token = page.next_page_token;
            if token.is_none() {
                break;
            }
            if diagnostic.pages >= self.limits.max_pages {
                return Err(self.bound_error(&diagnostic));
            }
        }

        diagnostic.operation = Some(Operation::Commit);
        let commit = self
            .store
            .commit(
                key,
                Some(raw_cursor.as_str()),
                &next_cursor,
                &effects,
                fault,
            )
            .map_err(|error| self.store_error(error, Operation::Commit, diagnostic.clone()))?;
        Ok(SyncOutcome::Incremental(SyncReport {
            cursor: next_cursor.as_str().to_owned(),
            diagnostic,
            commit,
        }))
    }

    fn reconcile(
        &mut self,
        key: &SyncKey,
        expected_cursor: Option<&str>,
        fallback: FallbackReason,
        fault: CommitFault,
        mut diagnostic: Diagnostic,
    ) -> Result<SyncOutcome, SyncError> {
        diagnostic.fallback = Some(fallback);
        for attempt in 1..=self.limits.max_scan_attempts {
            diagnostic.scan_attempts = attempt;
            let result = self.scan_once(key, &mut diagnostic);
            let (anchor, effects) = match result {
                Ok(value) => value,
                Err(ScanFailure::Restart) if attempt < self.limits.max_scan_attempts => continue,
                Err(ScanFailure::Restart) => return Err(self.bound_error(&diagnostic)),
                Err(ScanFailure::Sync(error)) => return Err(error),
            };
            diagnostic.operation = Some(Operation::Commit);
            let commit = self
                .store
                .commit(key, expected_cursor, &anchor, &effects, fault)
                .map_err(|error| self.store_error(error, Operation::Commit, diagnostic.clone()))?;
            return Ok(SyncOutcome::Reconciled(SyncReport {
                cursor: anchor.as_str().to_owned(),
                diagnostic,
                commit,
            }));
        }
        Err(self.bound_error(&diagnostic))
    }

    fn scan_once(
        &mut self,
        key: &SyncKey,
        diagnostic: &mut Diagnostic,
    ) -> Result<(HistoryId, Vec<SourceEffect>), ScanFailure> {
        diagnostic.operation = Some(Operation::ProfileHistory);
        self.consume_call(diagnostic).map_err(ScanFailure::Sync)?;
        let anchor = match self.gateway.profile_history_id() {
            Ok(value) => self
                .history_id(&value, diagnostic)
                .map_err(ScanFailure::Sync)?,
            Err(GatewayError::ReconciliationRestart) => return Err(ScanFailure::Restart),
            Err(error) => return Err(ScanFailure::Sync(self.gateway_error(error, diagnostic))),
        };

        let mut token = None;
        let mut pages = 0;
        let mut unique = HashSet::new();
        let mut effects = Vec::new();
        loop {
            diagnostic.operation = Some(Operation::ListMessages);
            self.consume_call(diagnostic).map_err(ScanFailure::Sync)?;
            let page = match self
                .gateway
                .list_messages(token.as_deref(), self.limits.page_size)
            {
                Ok(page) => page,
                Err(GatewayError::ReconciliationRestart) => return Err(ScanFailure::Restart),
                Err(error) => return Err(ScanFailure::Sync(self.gateway_error(error, diagnostic))),
            };
            pages += 1;
            diagnostic.pages += 1;
            for message_id in page.message_ids {
                if unique.contains(&message_id) {
                    continue;
                }
                if unique.len() >= self.limits.max_unique_messages {
                    return Err(ScanFailure::Sync(self.bound_error(diagnostic)));
                }
                unique.insert(message_id.clone());
                diagnostic.unique_messages += 1;
                diagnostic.operation = Some(Operation::GetMessage);
                self.consume_call(diagnostic).map_err(ScanFailure::Sync)?;
                match self.gateway.get_message(&message_id) {
                    Ok(message) => effects.push(
                        self.message_effect(key, &message_id, message, diagnostic)
                            .map_err(ScanFailure::Sync)?,
                    ),
                    Err(GatewayError::MessageNotFound) => {
                        let identity = SourceIdentity::new(key, message_id);
                        if self
                            .store
                            .source_id(&identity)
                            .map_err(|error| {
                                ScanFailure::Sync(self.store_error(
                                    error,
                                    Operation::Commit,
                                    diagnostic.clone(),
                                ))
                            })?
                            .is_some()
                        {
                            effects.push(SourceEffect {
                                identity,
                                revision: anchor.clone(),
                                available: false,
                                reason: AvailabilityReason::MessageNotFound,
                                evidence_fingerprint: "message-not-found".into(),
                            });
                        }
                    }
                    Err(GatewayError::ReconciliationRestart) => return Err(ScanFailure::Restart),
                    Err(error) => {
                        return Err(ScanFailure::Sync(self.gateway_error(error, diagnostic)))
                    }
                }
            }
            token = page.next_page_token;
            if token.is_none() {
                break;
            }
            if pages >= self.limits.max_pages {
                return Err(ScanFailure::Sync(self.bound_error(diagnostic)));
            }
        }
        Ok((anchor, effects))
    }

    fn message_effect(
        &self,
        key: &SyncKey,
        requested_message_id: &str,
        message: GmailMessage,
        diagnostic: &Diagnostic,
    ) -> Result<SourceEffect, SyncError> {
        if message.id != requested_message_id || message.evidence_fingerprint.is_empty() {
            return Err(self.error(
                SyncErrorKind::Invariant,
                DiagnosticError::Invariant,
                diagnostic,
            ));
        }
        Ok(SourceEffect {
            identity: SourceIdentity::new(key, message.id),
            revision: self.history_id(&message.history_id, diagnostic)?,
            available: true,
            reason: AvailabilityReason::Materialized,
            evidence_fingerprint: message.evidence_fingerprint,
        })
    }

    fn history_id(&self, value: &str, diagnostic: &Diagnostic) -> Result<HistoryId, SyncError> {
        HistoryId::parse(value).map_err(|_| {
            self.error(
                SyncErrorKind::Invariant,
                DiagnosticError::Invariant,
                diagnostic,
            )
        })
    }

    fn consume_call(&self, diagnostic: &mut Diagnostic) -> Result<(), SyncError> {
        if diagnostic.gateway_calls >= self.limits.max_gateway_calls {
            return Err(self.bound_error(diagnostic));
        }
        diagnostic.gateway_calls += 1;
        Ok(())
    }

    fn bound_error(&self, diagnostic: &Diagnostic) -> SyncError {
        self.error(
            SyncErrorKind::IncompleteBoundExceeded,
            DiagnosticError::BoundExceeded,
            diagnostic,
        )
    }

    fn gateway_error(&self, error: GatewayError, diagnostic: &Diagnostic) -> SyncError {
        let (kind, diagnostic_error) = match error {
            GatewayError::Authentication => (
                SyncErrorKind::Authentication,
                DiagnosticError::Authentication,
            ),
            GatewayError::Permission => (SyncErrorKind::Permission, DiagnosticError::Permission),
            GatewayError::Quota => (SyncErrorKind::Quota, DiagnosticError::Quota),
            GatewayError::RateLimited => (SyncErrorKind::RateLimited, DiagnosticError::RateLimited),
            GatewayError::Transient => (SyncErrorKind::Transient, DiagnosticError::Transient),
            GatewayError::MalformedRequest => (
                SyncErrorKind::MalformedRequest,
                DiagnosticError::MalformedRequest,
            ),
            GatewayError::MessageNotFound => (
                SyncErrorKind::MessageNotFound,
                DiagnosticError::MessageNotFound,
            ),
            GatewayError::Cancelled => (SyncErrorKind::Cancelled, DiagnosticError::Cancelled),
            GatewayError::UnexpectedScript => {
                (SyncErrorKind::UnexpectedScript, DiagnosticError::Script)
            }
            GatewayError::CursorExpired
            | GatewayError::CursorInvalid
            | GatewayError::ReconciliationRestart => {
                (SyncErrorKind::Invariant, DiagnosticError::Invariant)
            }
        };
        self.error(kind, diagnostic_error, diagnostic)
    }

    fn store_error(
        &self,
        error: StoreError,
        operation: Operation,
        mut diagnostic: Diagnostic,
    ) -> SyncError {
        diagnostic.operation = Some(operation);
        let (kind, diagnostic_error) = match error {
            StoreError::CompareAndSwap => (
                SyncErrorKind::CompareAndSwap,
                DiagnosticError::CompareAndSwap,
            ),
            StoreError::Conflict | StoreError::InvalidInput | StoreError::Invariant => {
                (SyncErrorKind::Invariant, DiagnosticError::Invariant)
            }
            StoreError::InterruptedBeforeCommit => {
                (SyncErrorKind::Cancelled, DiagnosticError::Cancelled)
            }
            StoreError::InterruptedAfterCommit | StoreError::Sqlite => {
                (SyncErrorKind::Store, DiagnosticError::Store)
            }
        };
        self.error(kind, diagnostic_error, &diagnostic)
    }

    fn error(
        &self,
        kind: SyncErrorKind,
        diagnostic_error: DiagnosticError,
        diagnostic: &Diagnostic,
    ) -> SyncError {
        let mut diagnostic = diagnostic.clone();
        diagnostic.error = Some(diagnostic_error);
        SyncError { kind, diagnostic }
    }
}

enum ScanFailure {
    Restart,
    Sync(SyncError),
}

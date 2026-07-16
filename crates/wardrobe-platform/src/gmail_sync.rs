use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::future::Future;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

pub const GMAIL_RAW_MESSAGE_LIMIT: usize = 25 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct HistoryId(String);

impl HistoryId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SyncError> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SyncError::MalformedResponse);
        }
        let canonical = value.trim_start_matches('0');
        Ok(Self(if canonical.is_empty() {
            "0".to_owned()
        } else {
            canonical.to_owned()
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn cmp_numeric(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.as_bytes().cmp(other.0.as_bytes()))
    }

    fn max(self, other: Self) -> Self {
        if self.cmp_numeric(&other).is_lt() {
            other
        } else {
            self
        }
    }
}

impl Ord for HistoryId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_numeric(other)
    }
}

impl PartialOrd for HistoryId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HistoryEventKind {
    MessageAdded,
    ScopedLabelAdded,
    ScopedLabelRemoved,
    MessageDeleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEvent {
    pub history_id: String,
    pub message_id: String,
    pub kind: HistoryEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessagePage {
    pub message_ids: Vec<String>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPage {
    pub events: Vec<HistoryEvent>,
    pub next_page_token: Option<String>,
    pub mailbox_history_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawGmailMessage {
    pub id: String,
    pub history_id: String,
    pub label_ids: Vec<String>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    HistoryNotFound,
    MessageNotFound,
    Authentication,
    Permission,
    RateLimited,
    Quota,
    Transport,
    Server,
    Timeout,
    MalformedRequest,
    MalformedResponse,
    Cancelled,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gmail gateway error: {self:?}")
    }
}

impl std::error::Error for GatewayError {}

pub trait GmailGateway {
    fn profile_history_id(&mut self) -> impl Future<Output = Result<String, GatewayError>> + Send;

    fn list_messages(
        &mut self,
        label_id: &str,
        page_token: Option<&str>,
        page_size: usize,
    ) -> impl Future<Output = Result<MessagePage, GatewayError>> + Send;

    fn get_message(
        &mut self,
        message_id: &str,
    ) -> impl Future<Output = Result<RawGmailMessage, GatewayError>> + Send;

    fn list_history(
        &mut self,
        start_history_id: &str,
        label_id: &str,
        page_token: Option<&str>,
        page_size: usize,
    ) -> impl Future<Output = Result<HistoryPage, GatewayError>> + Send;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncKey {
    pub account_key: String,
    pub scope_id: String,
    pub label_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncLimits {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_unique_messages: usize,
    pub max_total_raw_bytes: usize,
    pub max_gateway_calls: usize,
    pub max_scan_attempts: usize,
    pub operation_timeout: Duration,
}

impl SyncLimits {
    pub fn validate(self) -> Result<Self, SyncError> {
        if !(1..=100).contains(&self.page_size)
            || !(1..=10).contains(&self.max_pages)
            || !(1..=200).contains(&self.max_unique_messages)
            || !(1..=100 * 1024 * 1024).contains(&self.max_total_raw_bytes)
            || self.max_gateway_calls == 0
            || self.max_scan_attempts == 0
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(60)
        {
            return Err(SyncError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    LabelRemoved,
    MessageDeleted,
    MessageNotFound,
    LabelAbsentAfterFetch,
}

impl UnavailableReason {
    pub(crate) fn as_db(self) -> &'static str {
        match self {
            Self::LabelRemoved => "label_removed",
            Self::MessageDeleted => "message_deleted",
            Self::MessageNotFound => "message_not_found",
            Self::LabelAbsentAfterFetch => "label_absent_after_fetch",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevisionEffect {
    Available {
        message_id: String,
        revision: HistoryId,
        raw: Vec<u8>,
    },
    Unavailable {
        message_id: String,
        revision: HistoryId,
        reason: UnavailableReason,
    },
}

impl RevisionEffect {
    pub fn message_id(&self) -> &str {
        match self {
            Self::Available { message_id, .. } | Self::Unavailable { message_id, .. } => message_id,
        }
    }

    pub fn revision(&self) -> &HistoryId {
        match self {
            Self::Available { revision, .. } | Self::Unavailable { revision, .. } => revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    Incremental,
    Reconciled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncBatch {
    pub mode: SyncMode,
    pub expected_checkpoint: Option<String>,
    pub next_checkpoint: HistoryId,
    pub discovered_message_ids: Vec<String>,
    pub effects: Vec<RevisionEffect>,
    pub pages: usize,
    pub gateway_calls: usize,
    pub raw_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    InvalidConfiguration,
    ScopeTooLarge,
    Authentication,
    Permission,
    RateLimited,
    Quota,
    Transport,
    Server,
    Timeout,
    MalformedRequest,
    MalformedResponse,
    Cancelled,
    RevisionCollision,
    CompareAndSwap,
    Store,
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gmail synchronization failed: {self:?}")
    }
}

impl std::error::Error for SyncError {}

pub trait GmailSyncStore {
    fn checkpoint(&self, key: &SyncKey) -> Result<Option<String>, SyncError>;
    fn known_message_ids(&self, key: &SyncKey) -> Result<Vec<String>, SyncError>;
    fn commit(&self, key: &SyncKey, batch: &SyncBatch) -> Result<SyncCommit, SyncError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncCommit {
    pub sources_inserted: usize,
    pub revisions_inserted: usize,
    pub revisions_replayed: usize,
    pub evidence_generation: u64,
}

pub struct GmailHistoryCoordinator {
    limits: SyncLimits,
}

impl GmailHistoryCoordinator {
    pub fn new(limits: SyncLimits) -> Result<Self, SyncError> {
        Ok(Self {
            limits: limits.validate()?,
        })
    }

    pub async fn sync<G, S>(
        &self,
        gateway: &mut G,
        store: &S,
        key: &SyncKey,
    ) -> Result<(SyncBatch, SyncCommit), SyncError>
    where
        G: GmailGateway + Send,
        S: GmailSyncStore,
    {
        let batch = self.collect(gateway, store, key).await?;
        let commit = store.commit(key, &batch)?;
        Ok((batch, commit))
    }

    pub async fn collect<G, S>(
        &self,
        gateway: &mut G,
        store: &S,
        key: &SyncKey,
    ) -> Result<SyncBatch, SyncError>
    where
        G: GmailGateway + Send,
        S: GmailSyncStore,
    {
        validate_key(key)?;
        let checkpoint = store.checkpoint(key)?;
        let deadline = Instant::now() + self.limits.operation_timeout;
        let mut budget = Budget::default();
        let batch = match checkpoint
            .as_ref()
            .map(|value| HistoryId::parse(value.clone()))
        {
            None | Some(Err(_)) => {
                self.reconcile(
                    gateway,
                    store,
                    key,
                    checkpoint.clone(),
                    deadline,
                    &mut budget,
                )
                .await?
            }
            Some(Ok(cursor)) => {
                match self
                    .incremental(
                        gateway,
                        key,
                        checkpoint.clone().expect("checkpoint is present"),
                        cursor,
                        deadline,
                        &mut budget,
                    )
                    .await
                {
                    Ok(batch) => batch,
                    Err(SyncFailure::HistoryNotFound) => {
                        self.reconcile(
                            gateway,
                            store,
                            key,
                            checkpoint.clone(),
                            deadline,
                            &mut budget,
                        )
                        .await?
                    }
                    Err(SyncFailure::Fatal(error)) => return Err(error),
                    Err(SyncFailure::Restart) => return Err(SyncError::ScopeTooLarge),
                }
            }
        };
        Ok(batch)
    }

    async fn reconcile<G, S>(
        &self,
        gateway: &mut G,
        store: &S,
        key: &SyncKey,
        expected_checkpoint: Option<String>,
        deadline: Instant,
        budget: &mut Budget,
    ) -> Result<SyncBatch, SyncError>
    where
        G: GmailGateway + Send,
        S: GmailSyncStore,
    {
        let anchor = HistoryId::parse(
            self.call(deadline, budget, gateway.profile_history_id())
                .await
                .map_err(map_gateway)?,
        )?;
        let mut listed = BTreeSet::new();
        let mut token = None;
        let mut seen_tokens = HashSet::new();
        let mut pages = 0;
        loop {
            let page = self
                .call(
                    deadline,
                    budget,
                    gateway.list_messages(&key.label_id, token.as_deref(), self.limits.page_size),
                )
                .await
                .map_err(map_gateway)?;
            pages += 1;
            for message_id in page.message_ids {
                validate_provider_value(&message_id)?;
                listed.insert(message_id);
                if listed.len() > self.limits.max_unique_messages {
                    return Err(SyncError::ScopeTooLarge);
                }
            }
            token = validate_next_token(page.next_page_token, &mut seen_tokens)?;
            if token.is_none() {
                break;
            }
            if pages >= self.limits.max_pages {
                return Err(SyncError::ScopeTooLarge);
            }
        }

        let mut union = listed;
        for message_id in store.known_message_ids(key)? {
            validate_provider_value(&message_id)?;
            union.insert(message_id);
            if union.len() > self.limits.max_unique_messages {
                return Err(SyncError::ScopeTooLarge);
            }
        }
        let mut effects = Vec::with_capacity(union.len());
        for message_id in &union {
            match self
                .call(deadline, budget, gateway.get_message(message_id))
                .await
            {
                Ok(message) => {
                    validate_message(&message, message_id)?;
                    budget.consume_raw(message.raw.len(), self.limits)?;
                    let message_history = HistoryId::parse(message.history_id)?;
                    let revision = anchor.clone().max(message_history);
                    if message.label_ids.iter().any(|label| label == &key.label_id) {
                        effects.push(RevisionEffect::Available {
                            message_id: message_id.clone(),
                            revision,
                            raw: message.raw,
                        });
                    } else {
                        effects.push(RevisionEffect::Unavailable {
                            message_id: message_id.clone(),
                            revision,
                            reason: UnavailableReason::LabelAbsentAfterFetch,
                        });
                    }
                }
                Err(GatewayError::MessageNotFound) => {
                    effects.push(RevisionEffect::Unavailable {
                        message_id: message_id.clone(),
                        revision: anchor.clone(),
                        reason: UnavailableReason::MessageNotFound,
                    });
                }
                Err(error) => return Err(map_gateway(error)),
            }
        }
        Ok(SyncBatch {
            mode: SyncMode::Reconciled,
            expected_checkpoint,
            next_checkpoint: anchor,
            discovered_message_ids: union.into_iter().collect(),
            effects,
            pages,
            gateway_calls: budget.calls,
            raw_bytes: budget.raw_bytes,
        })
    }

    async fn incremental<G>(
        &self,
        gateway: &mut G,
        key: &SyncKey,
        expected_checkpoint: String,
        cursor: HistoryId,
        deadline: Instant,
        budget: &mut Budget,
    ) -> Result<SyncBatch, SyncFailure>
    where
        G: GmailGateway + Send,
    {
        for attempt in 0..self.limits.max_scan_attempts {
            match self
                .incremental_once(
                    gateway,
                    key,
                    expected_checkpoint.clone(),
                    cursor.clone(),
                    deadline,
                    budget,
                )
                .await
            {
                Err(SyncFailure::Restart) if attempt + 1 < self.limits.max_scan_attempts => {}
                result => return result,
            }
        }
        Err(SyncFailure::Fatal(SyncError::ScopeTooLarge))
    }

    async fn incremental_once<G>(
        &self,
        gateway: &mut G,
        key: &SyncKey,
        expected_checkpoint: String,
        cursor: HistoryId,
        deadline: Instant,
        budget: &mut Budget,
    ) -> Result<SyncBatch, SyncFailure>
    where
        G: GmailGateway + Send,
    {
        let mut events = Vec::new();
        let mut exact_events = BTreeSet::new();
        let mut token = None;
        let mut seen_tokens = HashSet::new();
        let mut pages = 0;
        let mut terminal = cursor.clone();
        loop {
            let page = match self
                .call(
                    deadline,
                    budget,
                    gateway.list_history(
                        cursor.as_str(),
                        &key.label_id,
                        token.as_deref(),
                        self.limits.page_size,
                    ),
                )
                .await
            {
                Err(GatewayError::HistoryNotFound) => return Err(SyncFailure::HistoryNotFound),
                Err(error) => return Err(SyncFailure::Fatal(map_gateway(error))),
                Ok(page) => page,
            };
            pages += 1;
            let page_cursor =
                HistoryId::parse(page.mailbox_history_id).map_err(SyncFailure::Fatal)?;
            if page_cursor < terminal {
                return Err(SyncFailure::Fatal(SyncError::MalformedResponse));
            }
            terminal = page_cursor;
            for event in page.events {
                validate_provider_value(&event.message_id).map_err(SyncFailure::Fatal)?;
                let history = HistoryId::parse(event.history_id).map_err(SyncFailure::Fatal)?;
                if history <= cursor || history > terminal {
                    return Err(SyncFailure::Fatal(SyncError::MalformedResponse));
                }
                let identity = (
                    history.as_str().to_owned(),
                    event.message_id.clone(),
                    event.kind,
                );
                if exact_events.insert(identity) {
                    events.push((history, event.message_id, event.kind));
                }
            }
            token = validate_next_token(page.next_page_token, &mut seen_tokens)
                .map_err(SyncFailure::Fatal)?;
            if token.is_none() {
                break;
            }
            if pages >= self.limits.max_pages {
                return Err(SyncFailure::Fatal(SyncError::ScopeTooLarge));
            }
        }

        events.sort_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.2.cmp(&right.2))
        });
        let mut final_events = BTreeMap::new();
        for (history, message_id, kind) in events {
            final_events.insert(message_id, (history, kind));
        }
        if final_events.len() > self.limits.max_unique_messages {
            return Err(SyncFailure::Fatal(SyncError::ScopeTooLarge));
        }

        let mut effects = Vec::with_capacity(final_events.len());
        for (message_id, (selected, kind)) in &final_events {
            match kind {
                HistoryEventKind::MessageAdded | HistoryEventKind::ScopedLabelAdded => {
                    match self
                        .call(deadline, budget, gateway.get_message(message_id))
                        .await
                    {
                        Ok(message) => {
                            validate_message(&message, message_id).map_err(SyncFailure::Fatal)?;
                            budget
                                .consume_raw(message.raw.len(), self.limits)
                                .map_err(SyncFailure::Fatal)?;
                            let fetched =
                                HistoryId::parse(message.history_id).map_err(SyncFailure::Fatal)?;
                            if fetched > terminal {
                                return Err(SyncFailure::Restart);
                            }
                            let revision = selected.clone().max(fetched);
                            if message.label_ids.iter().any(|label| label == &key.label_id) {
                                effects.push(RevisionEffect::Available {
                                    message_id: message_id.clone(),
                                    revision,
                                    raw: message.raw,
                                });
                            } else {
                                effects.push(RevisionEffect::Unavailable {
                                    message_id: message_id.clone(),
                                    revision,
                                    reason: UnavailableReason::LabelAbsentAfterFetch,
                                });
                            }
                        }
                        Err(GatewayError::MessageNotFound) => {
                            effects.push(RevisionEffect::Unavailable {
                                message_id: message_id.clone(),
                                revision: selected.clone(),
                                reason: UnavailableReason::MessageNotFound,
                            });
                        }
                        Err(error) => return Err(SyncFailure::Fatal(map_gateway(error))),
                    }
                }
                HistoryEventKind::ScopedLabelRemoved => {
                    effects.push(RevisionEffect::Unavailable {
                        message_id: message_id.clone(),
                        revision: selected.clone(),
                        reason: UnavailableReason::LabelRemoved,
                    });
                }
                HistoryEventKind::MessageDeleted => {
                    effects.push(RevisionEffect::Unavailable {
                        message_id: message_id.clone(),
                        revision: selected.clone(),
                        reason: UnavailableReason::MessageDeleted,
                    });
                }
            }
        }
        Ok(SyncBatch {
            mode: SyncMode::Incremental,
            expected_checkpoint: Some(expected_checkpoint),
            next_checkpoint: terminal,
            discovered_message_ids: final_events.into_keys().collect(),
            effects,
            pages,
            gateway_calls: budget.calls,
            raw_bytes: budget.raw_bytes,
        })
    }

    async fn call<T>(
        &self,
        deadline: Instant,
        budget: &mut Budget,
        future: impl Future<Output = Result<T, GatewayError>>,
    ) -> Result<T, GatewayError> {
        if budget.calls >= self.limits.max_gateway_calls {
            return Err(GatewayError::Cancelled);
        }
        budget.calls += 1;
        timeout_at(deadline, future)
            .await
            .map_err(|_| GatewayError::Timeout)?
    }
}

#[derive(Default)]
struct Budget {
    calls: usize,
    raw_bytes: usize,
}

impl Budget {
    fn consume_raw(&mut self, length: usize, limits: SyncLimits) -> Result<(), SyncError> {
        if length > GMAIL_RAW_MESSAGE_LIMIT {
            return Err(SyncError::MalformedResponse);
        }
        self.raw_bytes = self
            .raw_bytes
            .checked_add(length)
            .ok_or(SyncError::ScopeTooLarge)?;
        if self.raw_bytes > limits.max_total_raw_bytes {
            return Err(SyncError::ScopeTooLarge);
        }
        Ok(())
    }
}

enum SyncFailure {
    HistoryNotFound,
    Restart,
    Fatal(SyncError),
}

fn validate_key(key: &SyncKey) -> Result<(), SyncError> {
    if key.account_key.len() != 64
        || !key
            .account_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || uuid::Uuid::parse_str(&key.scope_id).is_err()
    {
        return Err(SyncError::InvalidConfiguration);
    }
    validate_provider_value(&key.label_id)
}

fn validate_provider_value(value: &str) -> Result<(), SyncError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(SyncError::MalformedResponse);
    }
    Ok(())
}

fn validate_message(message: &RawGmailMessage, requested_id: &str) -> Result<(), SyncError> {
    if message.id != requested_id {
        return Err(SyncError::MalformedResponse);
    }
    validate_provider_value(&message.id)?;
    for label in &message.label_ids {
        validate_provider_value(label)?;
    }
    if message.raw.len() > GMAIL_RAW_MESSAGE_LIMIT {
        return Err(SyncError::MalformedResponse);
    }
    Ok(())
}

fn validate_next_token(
    token: Option<String>,
    seen: &mut HashSet<String>,
) -> Result<Option<String>, SyncError> {
    let Some(token) = token else {
        return Ok(None);
    };
    validate_provider_value(&token)?;
    if !seen.insert(token.clone()) {
        return Err(SyncError::MalformedResponse);
    }
    Ok(Some(token))
}

fn map_gateway(error: GatewayError) -> SyncError {
    match error {
        GatewayError::Authentication => SyncError::Authentication,
        GatewayError::Permission => SyncError::Permission,
        GatewayError::RateLimited => SyncError::RateLimited,
        GatewayError::Quota => SyncError::Quota,
        GatewayError::Transport => SyncError::Transport,
        GatewayError::Server => SyncError::Server,
        GatewayError::Timeout => SyncError::Timeout,
        GatewayError::MalformedRequest => SyncError::MalformedRequest,
        GatewayError::MalformedResponse
        | GatewayError::HistoryNotFound
        | GatewayError::MessageNotFound => SyncError::MalformedResponse,
        GatewayError::Cancelled => SyncError::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Store {
        checkpoint: Option<String>,
        known: Vec<String>,
        batch: Mutex<Option<SyncBatch>>,
    }

    impl GmailSyncStore for Store {
        fn checkpoint(&self, _key: &SyncKey) -> Result<Option<String>, SyncError> {
            Ok(self.checkpoint.clone())
        }

        fn known_message_ids(&self, _key: &SyncKey) -> Result<Vec<String>, SyncError> {
            Ok(self.known.clone())
        }

        fn commit(&self, _key: &SyncKey, batch: &SyncBatch) -> Result<SyncCommit, SyncError> {
            *self.batch.lock().unwrap() = Some(batch.clone());
            Ok(SyncCommit::default())
        }
    }

    enum Step {
        Profile(&'static str),
        Messages(MessagePage),
        History(Result<HistoryPage, GatewayError>),
        Message(&'static str, Result<RawGmailMessage, GatewayError>),
    }

    struct Gateway {
        steps: VecDeque<Step>,
        gets: Vec<String>,
    }

    impl Gateway {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                gets: Vec::new(),
            }
        }

        fn next(&mut self) -> Step {
            self.steps.pop_front().expect("script exhausted")
        }
    }

    impl GmailGateway for Gateway {
        async fn profile_history_id(&mut self) -> Result<String, GatewayError> {
            match self.next() {
                Step::Profile(value) => Ok(value.to_owned()),
                _ => panic!("unexpected profile call"),
            }
        }

        async fn list_messages(
            &mut self,
            _label_id: &str,
            _page_token: Option<&str>,
            _page_size: usize,
        ) -> Result<MessagePage, GatewayError> {
            match self.next() {
                Step::Messages(page) => Ok(page),
                _ => panic!("unexpected message list call"),
            }
        }

        async fn get_message(&mut self, message_id: &str) -> Result<RawGmailMessage, GatewayError> {
            self.gets.push(message_id.to_owned());
            match self.next() {
                Step::Message(expected, result) => {
                    assert_eq!(expected, message_id);
                    result
                }
                _ => panic!("unexpected get call"),
            }
        }

        async fn list_history(
            &mut self,
            _start_history_id: &str,
            _label_id: &str,
            _page_token: Option<&str>,
            _page_size: usize,
        ) -> Result<HistoryPage, GatewayError> {
            match self.next() {
                Step::History(result) => result,
                _ => panic!("unexpected history call"),
            }
        }
    }

    fn limits() -> SyncLimits {
        SyncLimits {
            page_size: 2,
            max_pages: 4,
            max_unique_messages: 8,
            max_total_raw_bytes: 1024,
            max_gateway_calls: 32,
            max_scan_attempts: 2,
            operation_timeout: Duration::from_secs(2),
        }
    }

    fn key() -> SyncKey {
        SyncKey {
            account_key: "a".repeat(64),
            scope_id: "11111111-1111-4111-8111-111111111111".into(),
            label_id: "Label_1".into(),
        }
    }

    fn raw(id: &str, history: &str, labels: &[&str]) -> RawGmailMessage {
        RawGmailMessage {
            id: id.into(),
            history_id: history.into(),
            label_ids: labels.iter().map(|value| (*value).to_owned()).collect(),
            raw: b"Subject: receipt\r\n\r\nbody".to_vec(),
        }
    }

    #[tokio::test]
    async fn incremental_collects_then_folds_numeric_history_with_delete_precedence() {
        let store = Store {
            checkpoint: Some("9".into()),
            ..Store::default()
        };
        let mut gateway = Gateway::new([
            Step::History(Ok(HistoryPage {
                events: vec![
                    HistoryEvent {
                        history_id: "10".into(),
                        message_id: "m1".into(),
                        kind: HistoryEventKind::MessageDeleted,
                    },
                    HistoryEvent {
                        history_id: "10".into(),
                        message_id: "m1".into(),
                        kind: HistoryEventKind::ScopedLabelAdded,
                    },
                    HistoryEvent {
                        history_id: "11".into(),
                        message_id: "m2".into(),
                        kind: HistoryEventKind::MessageDeleted,
                    },
                ],
                next_page_token: Some("next".into()),
                mailbox_history_id: "11".into(),
            })),
            Step::History(Ok(HistoryPage {
                events: vec![HistoryEvent {
                    history_id: "12".into(),
                    message_id: "m1".into(),
                    kind: HistoryEventKind::ScopedLabelAdded,
                }],
                next_page_token: None,
                mailbox_history_id: "12".into(),
            })),
            Step::Message("m1", Ok(raw("m1", "12", &["Label_1"]))),
        ]);
        let coordinator = GmailHistoryCoordinator::new(limits()).unwrap();
        let (batch, _) = coordinator
            .sync(&mut gateway, &store, &key())
            .await
            .unwrap();
        assert_eq!(gateway.gets, ["m1"]);
        assert_eq!(batch.next_checkpoint.as_str(), "12");
        assert!(matches!(
            &batch.effects[0],
            RevisionEffect::Available { message_id, .. } if message_id == "m1"
        ));
        assert!(matches!(
            &batch.effects[1],
            RevisionEffect::Unavailable {
                message_id,
                reason: UnavailableReason::MessageDeleted,
                ..
            } if message_id == "m2"
        ));
    }

    #[tokio::test]
    async fn expired_history_reconciles_listed_union_known_unlisted_once() {
        let store = Store {
            checkpoint: Some("7".into()),
            known: vec!["known".into()],
            ..Store::default()
        };
        let mut gateway = Gateway::new([
            Step::History(Err(GatewayError::HistoryNotFound)),
            Step::Profile("20"),
            Step::Messages(MessagePage {
                message_ids: vec!["listed".into()],
                next_page_token: None,
            }),
            Step::Message("known", Ok(raw("known", "21", &[]))),
            Step::Message("listed", Err(GatewayError::MessageNotFound)),
        ]);
        let coordinator = GmailHistoryCoordinator::new(limits()).unwrap();
        let (batch, _) = coordinator
            .sync(&mut gateway, &store, &key())
            .await
            .unwrap();
        assert_eq!(gateway.gets, ["known", "listed"]);
        assert_eq!(batch.next_checkpoint.as_str(), "20");
        assert_eq!(batch.discovered_message_ids, ["known", "listed"]);
        assert_eq!(batch.effects[0].revision().as_str(), "21");
        assert_eq!(batch.effects[1].revision().as_str(), "20");
    }

    #[test]
    fn history_ids_use_canonical_unbounded_numeric_order() {
        assert!(HistoryId::parse("x").is_err());
        assert_eq!(HistoryId::parse("0009").unwrap().as_str(), "9");
        assert!(
            HistoryId::parse("100000000000000000000").unwrap()
                > HistoryId::parse("99999999999999999999").unwrap()
        );
    }
}

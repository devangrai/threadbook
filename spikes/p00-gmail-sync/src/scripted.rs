use crate::gmail::{GatewayError, GmailGateway, GmailMessage, HistoryPage, MessagePage, Operation};
use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub enum ScriptStep {
    Profile(Result<String, GatewayError>),
    ListMessages {
        token: Option<String>,
        result: Result<MessagePage, GatewayError>,
    },
    GetMessage {
        id: String,
        result: Result<GmailMessage, GatewayError>,
    },
    ListHistory {
        start: String,
        token: Option<String>,
        result: Result<HistoryPage, GatewayError>,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallCounts {
    pub profile: usize,
    pub list_messages: usize,
    pub get_message: usize,
    pub list_history: usize,
}

impl CallCounts {
    pub fn total(self) -> usize {
        self.profile + self.list_messages + self.get_message + self.list_history
    }
}

#[derive(Debug)]
pub struct ScriptedGmailGateway {
    steps: VecDeque<ScriptStep>,
    calls: CallCounts,
    operations: Vec<Operation>,
}

impl ScriptedGmailGateway {
    pub fn new(steps: impl IntoIterator<Item = ScriptStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            calls: CallCounts::default(),
            operations: Vec::new(),
        }
    }

    pub fn calls(&self) -> CallCounts {
        self.calls
    }

    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn assert_exhausted(&self) {
        assert!(self.steps.is_empty(), "script has unconsumed steps");
    }

    fn next(&mut self, operation: Operation) -> Result<ScriptStep, GatewayError> {
        self.operations.push(operation);
        self.steps.pop_front().ok_or(GatewayError::UnexpectedScript)
    }
}

impl GmailGateway for ScriptedGmailGateway {
    fn profile_history_id(&mut self) -> Result<String, GatewayError> {
        self.calls.profile += 1;
        match self.next(Operation::ProfileHistory)? {
            ScriptStep::Profile(result) => result,
            _ => Err(GatewayError::UnexpectedScript),
        }
    }

    fn list_messages(
        &mut self,
        page_token: Option<&str>,
        _page_size: usize,
    ) -> Result<MessagePage, GatewayError> {
        self.calls.list_messages += 1;
        match self.next(Operation::ListMessages)? {
            ScriptStep::ListMessages { token, result } if token.as_deref() == page_token => result,
            _ => Err(GatewayError::UnexpectedScript),
        }
    }

    fn get_message(&mut self, message_id: &str) -> Result<GmailMessage, GatewayError> {
        self.calls.get_message += 1;
        match self.next(Operation::GetMessage)? {
            ScriptStep::GetMessage { id, result } if id == message_id => result,
            _ => Err(GatewayError::UnexpectedScript),
        }
    }

    fn list_history(
        &mut self,
        start_history_id: &str,
        page_token: Option<&str>,
        _page_size: usize,
    ) -> Result<HistoryPage, GatewayError> {
        self.calls.list_history += 1;
        match self.next(Operation::ListHistory)? {
            ScriptStep::ListHistory {
                start,
                token,
                result,
            } if start == start_history_id && token.as_deref() == page_token => {
                result.map(|mut page| {
                    // Gmail's startHistoryId is exclusive.
                    page.events
                        .retain(|event| decimal_after(&event.history_id, start_history_id));
                    page
                })
            }
            _ => Err(GatewayError::UnexpectedScript),
        }
    }
}

fn decimal_after(left: &str, right: &str) -> bool {
    fn normalize(value: &str) -> &str {
        let value = value.trim_start_matches('0');
        if value.is_empty() {
            "0"
        } else {
            value
        }
    }
    let left = normalize(left);
    let right = normalize(right);
    left.len() > right.len() || (left.len() == right.len() && left.as_bytes() > right.as_bytes())
}

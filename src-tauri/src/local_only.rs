use std::sync::{Arc, Condvar, Mutex};
use wardrobe_core::LocalOnlyAuthorityHealthV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundCapability {
    GmailAuthorize,
    GmailSync,
    GmailRevoke,
    ReceiptImageFetch,
    PhotoKitMaterialize,
    OpenAiRecommendation,
    OpenAiReceiptIntelligence,
    OpenAiTryOn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutboundAuthoritySnapshot {
    pub local_only: bool,
    pub revision: u64,
    pub health: LocalOnlyAuthorityHealthV1,
}

#[derive(Clone, Debug)]
pub(crate) struct OutboundAuthority {
    shared: Arc<SharedAuthority>,
}

#[derive(Debug)]
struct SharedAuthority {
    state: Mutex<AuthorityState>,
    idle: Condvar,
}

#[derive(Clone, Copy, Debug)]
struct AuthorityState {
    snapshot: OutboundAuthoritySnapshot,
    transitioning: bool,
    active_leases: usize,
}

#[derive(Debug)]
pub(crate) struct OutboundLease {
    shared: Arc<SharedAuthority>,
    _capability: Option<OutboundCapability>,
}

#[derive(Debug)]
pub(crate) struct OutboundTransition {
    authority: OutboundAuthority,
    prior: OutboundAuthoritySnapshot,
    completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityError {
    Denied,
    TransitionInProgress,
}

impl OutboundAuthority {
    pub(crate) fn new(snapshot: OutboundAuthoritySnapshot) -> Self {
        Self {
            shared: Arc::new(SharedAuthority {
                state: Mutex::new(AuthorityState {
                    snapshot,
                    transitioning: false,
                    active_leases: 0,
                }),
                idle: Condvar::new(),
            }),
        }
    }

    pub(crate) fn snapshot(&self) -> OutboundAuthoritySnapshot {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot
    }

    #[cfg(test)]
    pub(crate) fn active_leases_for_test(&self) -> usize {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_leases
    }

    pub(crate) fn acquire(
        &self,
        capability: OutboundCapability,
    ) -> Result<OutboundLease, AuthorityError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.transitioning {
            return Err(AuthorityError::TransitionInProgress);
        }
        if state.snapshot.local_only {
            return Err(AuthorityError::Denied);
        }
        state.active_leases = state
            .active_leases
            .checked_add(1)
            .expect("bounded process lease count");
        Ok(OutboundLease {
            shared: Arc::clone(&self.shared),
            _capability: Some(capability),
        })
    }

    pub(crate) fn acquire_local_cleanup(&self) -> Result<OutboundLease, AuthorityError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.transitioning {
            return Err(AuthorityError::TransitionInProgress);
        }
        state.active_leases = state
            .active_leases
            .checked_add(1)
            .expect("bounded process lease count");
        Ok(OutboundLease {
            shared: Arc::clone(&self.shared),
            _capability: None,
        })
    }

    pub(crate) fn begin_transition(&self) -> Result<OutboundTransition, AuthorityError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.transitioning {
            return Err(AuthorityError::TransitionInProgress);
        }
        state.transitioning = true;
        while state.active_leases != 0 {
            state = self
                .shared
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        Ok(OutboundTransition {
            authority: self.clone(),
            prior: state.snapshot,
            completed: false,
        })
    }
}

impl OutboundTransition {
    pub(crate) fn publish(mut self, snapshot: OutboundAuthoritySnapshot) {
        let mut state = self
            .authority
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.snapshot = snapshot;
        state.transitioning = false;
        self.completed = true;
        self.authority.shared.idle.notify_all();
    }

    pub(crate) fn fail_closed(mut self) {
        let mut state = self
            .authority
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.snapshot = OutboundAuthoritySnapshot {
            local_only: true,
            revision: self.prior.revision,
            health: if self.prior.revision == 0 {
                LocalOnlyAuthorityHealthV1::FailClosedDefault
            } else {
                LocalOnlyAuthorityHealthV1::FailClosedUncertain
            },
        };
        state.transitioning = false;
        self.completed = true;
        self.authority.shared.idle.notify_all();
    }
}

impl Drop for OutboundTransition {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self
            .authority
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.snapshot = self.prior;
        state.transitioning = false;
        self.authority.shared.idle.notify_all();
    }
}

impl Drop for OutboundLease {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active_leases = state.active_leases.saturating_sub(1);
        if state.active_leases == 0 {
            self.shared.idle.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn live_authority() -> OutboundAuthority {
        OutboundAuthority::new(OutboundAuthoritySnapshot {
            local_only: false,
            revision: 4,
            health: LocalOnlyAuthorityHealthV1::Persisted,
        })
    }

    #[test]
    fn local_only_denies_every_closed_capability() {
        let authority = OutboundAuthority::new(OutboundAuthoritySnapshot {
            local_only: true,
            revision: 1,
            health: LocalOnlyAuthorityHealthV1::Persisted,
        });
        for capability in [
            OutboundCapability::GmailAuthorize,
            OutboundCapability::GmailSync,
            OutboundCapability::GmailRevoke,
            OutboundCapability::ReceiptImageFetch,
            OutboundCapability::PhotoKitMaterialize,
            OutboundCapability::OpenAiRecommendation,
            OutboundCapability::OpenAiReceiptIntelligence,
            OutboundCapability::OpenAiTryOn,
        ] {
            assert_eq!(
                authority.acquire(capability).unwrap_err(),
                AuthorityError::Denied
            );
        }
    }

    #[test]
    fn transition_drains_revocation_and_blocks_new_work() {
        let authority = live_authority();
        let revocation = authority.acquire(OutboundCapability::GmailRevoke).unwrap();
        let transitioning = authority.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let transition = transitioning.begin_transition().unwrap();
            transition.publish(OutboundAuthoritySnapshot {
                local_only: true,
                revision: 5,
                health: LocalOnlyAuthorityHealthV1::Persisted,
            });
            finished_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        thread::sleep(Duration::from_millis(25));
        assert!(finished_rx.try_recv().is_err());
        assert_eq!(
            authority
                .acquire(OutboundCapability::OpenAiRecommendation)
                .unwrap_err(),
            AuthorityError::TransitionInProgress
        );
        drop(revocation);
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        thread.join().unwrap();
        assert!(authority.snapshot().local_only);
    }

    #[test]
    fn uncertain_publication_is_fail_closed_at_the_repairable_prior_revision() {
        let authority = live_authority();
        let transition = authority.begin_transition().unwrap();
        transition.fail_closed();
        assert_eq!(
            authority.snapshot(),
            OutboundAuthoritySnapshot {
                local_only: true,
                revision: 4,
                health: LocalOnlyAuthorityHealthV1::FailClosedUncertain,
            }
        );
        assert_eq!(
            authority
                .acquire(OutboundCapability::GmailAuthorize)
                .unwrap_err(),
            AuthorityError::Denied
        );
        assert!(authority.begin_transition().is_ok());
    }
}

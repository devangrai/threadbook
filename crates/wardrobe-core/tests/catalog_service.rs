use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use wardrobe_core::*;

#[derive(Clone)]
struct StoredDecision {
    decision_id: DecisionId,
    before_items: BTreeMap<ItemId, CatalogItemV1>,
}

#[derive(Default)]
struct State {
    revision: u64,
    evidence_generation: u64,
    items: BTreeMap<ItemId, CatalogItemV1>,
    decisions: Vec<StoredDecision>,
    undone: BTreeSet<DecisionId>,
}

#[derive(Clone, Default)]
struct MemoryCatalog {
    state: Rc<RefCell<State>>,
}

impl MemoryCatalog {
    fn require_revision(state: &State, expected: u64) -> CatalogPortResult<()> {
        if state.revision == expected {
            Ok(())
        } else {
            Err(CatalogPortError::new(CatalogPortErrorKind::Conflict))
        }
    }

    fn decision(
        kind: DecisionKindV1,
        affected_item_ids: Vec<ItemId>,
        affected_evidence_ids: Vec<EvidenceId>,
        compensates_decision_id: Option<DecisionId>,
    ) -> DecisionSnapshotV1 {
        DecisionSnapshotV1 {
            decision_id: DecisionId::new_v4(),
            kind,
            affected_item_ids,
            affected_evidence_ids,
            compensates_decision_id,
            reversible: true,
        }
    }

    fn decision_count(&self) -> usize {
        self.state.borrow().decisions.len()
    }

    fn revision(&self) -> u64 {
        self.state.borrow().revision
    }
}

impl CatalogPort for MemoryCatalog {
    fn import_local_sources(
        &self,
        request: &ImportLocalSourcesV1Request,
    ) -> CatalogPortResult<ImportLocalSourcesV1Response> {
        let mut state = self.state.borrow_mut();
        state.evidence_generation += 1;
        Ok(ImportLocalSourcesV1Response {
            schema_version: 1,
            request_id: request.request_id,
            summaries: request
                .paths
                .iter()
                .map(|_| ImportSummaryV1 {
                    import_root_id: Some(ImportRootId::new_v4()),
                    source_id: None,
                    imported: 1,
                    reused: 0,
                    quarantined: 0,
                    skipped: 0,
                    unavailable: 0,
                })
                .collect(),
            evidence_generation: state.evidence_generation,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn refresh_import_roots(
        &self,
        request: &RefreshImportRootsV1Request,
    ) -> CatalogPortResult<RefreshImportRootsV1Response> {
        Ok(RefreshImportRootsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            summaries: vec![],
            evidence_generation: self.state.borrow().evidence_generation,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn list_catalog(
        &self,
        request: &ListCatalogV1Request,
    ) -> CatalogPortResult<ListCatalogV1Response> {
        let state = self.state.borrow();
        let start = request
            .cursor
            .as_ref()
            .map(|cursor| cursor.as_str().parse::<usize>().unwrap())
            .unwrap_or(0);
        let items = state
            .items
            .values()
            .skip(start)
            .take(usize::from(request.limit))
            .cloned()
            .collect::<Vec<_>>();
        let next = start + items.len();
        Ok(ListCatalogV1Response {
            schema_version: 1,
            request_id: request.request_id,
            items,
            total_count: state.items.len() as u64,
            catalog_revision: state.revision,
            evidence_generation: state.evidence_generation,
            next_cursor: (next < state.items.len())
                .then(|| PageCursorV1::new(next.to_string()).unwrap()),
        })
    }

    fn list_inbox(&self, request: &ListInboxV1Request) -> CatalogPortResult<ListInboxV1Response> {
        Ok(ListInboxV1Response {
            schema_version: 1,
            request_id: request.request_id,
            evidence: vec![],
            quarantines: vec![],
            total_count: 0,
            catalog_revision: self.state.borrow().revision,
            evidence_generation: self.state.borrow().evidence_generation,
            next_cursor: None,
        })
    }

    fn save_item_and_append_decision(
        &self,
        request: &SaveItemV1Request,
    ) -> CatalogPortResult<SaveItemV1Response> {
        let mut state = self.state.borrow_mut();
        Self::require_revision(&state, request.expected_catalog_revision)?;
        let before_items = state.items.clone();
        let item_id = request.item_id.unwrap_or_else(ItemId::new_v4);
        let decision = Self::decision(
            DecisionKindV1::SaveItem,
            vec![item_id],
            request.evidence_ids.clone(),
            None,
        );
        let item = CatalogItemV1 {
            item_id,
            attributes: request.attributes.clone(),
            evidence_ids: request.evidence_ids.clone(),
            last_decision_id: decision.decision_id,
        };
        state.items.insert(item_id, item.clone());
        state.revision += 1;
        state.decisions.push(StoredDecision {
            decision_id: decision.decision_id,
            before_items,
        });
        Ok(SaveItemV1Response {
            schema_version: 1,
            request_id: request.request_id,
            item,
            decision,
            new_catalog_revision: state.revision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn decide_evidence_and_append_decision(
        &self,
        request: &DecideEvidenceV1Request,
    ) -> CatalogPortResult<DecideEvidenceV1Response> {
        let mut state = self.state.borrow_mut();
        Self::require_revision(&state, request.expected_catalog_revision)?;
        if request
            .item_id
            .is_some_and(|item_id| !state.items.contains_key(&item_id))
        {
            return Err(CatalogPortError::new(CatalogPortErrorKind::NotFound));
        }
        let before_items = state.items.clone();
        let evidence_state = match request.action {
            EvidenceDecisionActionV1::Assign => EvidenceStateV1::Assigned,
            EvidenceDecisionActionV1::Reject => EvidenceStateV1::Rejected,
            EvidenceDecisionActionV1::Defer => EvidenceStateV1::Deferred,
        };
        let decision = Self::decision(
            DecisionKindV1::DecideEvidence,
            request.item_id.into_iter().collect(),
            vec![request.evidence_id],
            None,
        );
        state.revision += 1;
        state.decisions.push(StoredDecision {
            decision_id: decision.decision_id,
            before_items,
        });
        Ok(DecideEvidenceV1Response {
            schema_version: 1,
            request_id: request.request_id,
            evidence: EvidenceSnapshotV1 {
                evidence_id: request.evidence_id,
                source: SourceSnapshotV1 {
                    source_id: SourceId::new_v4(),
                    import_root_id: None,
                    parent_source_id: None,
                    kind: ImportSourceKindV1::ImageFile,
                    availability: SourceAvailabilityV1::Present,
                    provenance_label: "/tmp/synthetic.jpg".to_owned(),
                    raw_blob_sha256: Some("a".repeat(64)),
                },
                kind: EvidenceKindV1::Image,
                state: evidence_state,
                assigned_item_id: request.item_id,
                review_label: "Imported image".to_owned(),
            },
            decision,
            new_catalog_revision: state.revision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn merge_items_and_append_decision(
        &self,
        request: &MergeItemsV1Request,
    ) -> CatalogPortResult<MergeItemsV1Response> {
        let mut state = self.state.borrow_mut();
        Self::require_revision(&state, request.expected_catalog_revision)?;
        if request
            .item_ids
            .iter()
            .any(|item_id| !state.items.contains_key(item_id))
        {
            return Err(CatalogPortError::new(CatalogPortErrorKind::NotFound));
        }
        let before_items = state.items.clone();
        let target_id = request.item_ids[0];
        let mut evidence_ids = request
            .item_ids
            .iter()
            .flat_map(|item_id| state.items[item_id].evidence_ids.iter().copied())
            .collect::<Vec<_>>();
        evidence_ids.sort_unstable();
        evidence_ids.dedup();
        let decision = Self::decision(
            DecisionKindV1::MergeItems,
            request.item_ids.clone(),
            evidence_ids.clone(),
            None,
        );
        for item_id in &request.item_ids {
            state.items.remove(item_id);
        }
        let item = CatalogItemV1 {
            item_id: target_id,
            attributes: request.target_attributes.clone(),
            evidence_ids,
            last_decision_id: decision.decision_id,
        };
        state.items.insert(target_id, item.clone());
        state.revision += 1;
        state.decisions.push(StoredDecision {
            decision_id: decision.decision_id,
            before_items,
        });
        Ok(MergeItemsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            item,
            decision,
            new_catalog_revision: state.revision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn split_item_and_append_decision(
        &self,
        request: &SplitItemV1Request,
    ) -> CatalogPortResult<SplitItemV1Response> {
        let mut state = self.state.borrow_mut();
        Self::require_revision(&state, request.expected_catalog_revision)?;
        if !state.items.contains_key(&request.item_id) {
            return Err(CatalogPortError::new(CatalogPortErrorKind::NotFound));
        }
        let before_items = state.items.clone();
        state.items.remove(&request.item_id);
        let mut items = request
            .groups
            .iter()
            .enumerate()
            .map(|(index, group)| CatalogItemV1 {
                item_id: if index == 0 {
                    request.item_id
                } else {
                    ItemId::new_v4()
                },
                attributes: group.attributes.clone(),
                evidence_ids: group.evidence_ids.clone(),
                last_decision_id: DecisionId::new_v4(),
            })
            .collect::<Vec<_>>();
        let mut affected_item_ids = vec![request.item_id];
        affected_item_ids.extend(items.iter().map(|item| item.item_id));
        affected_item_ids.sort_unstable();
        affected_item_ids.dedup();
        let decision = Self::decision(
            DecisionKindV1::SplitItem,
            affected_item_ids,
            request
                .groups
                .iter()
                .flat_map(|group| group.evidence_ids.iter().copied())
                .collect(),
            None,
        );
        for item in &mut items {
            item.last_decision_id = decision.decision_id;
            state.items.insert(item.item_id, item.clone());
        }
        state.revision += 1;
        state.decisions.push(StoredDecision {
            decision_id: decision.decision_id,
            before_items,
        });
        Ok(SplitItemV1Response {
            schema_version: 1,
            request_id: request.request_id,
            items,
            decision,
            new_catalog_revision: state.revision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn append_compensating_undo(
        &self,
        request: &UndoDecisionV1Request,
    ) -> CatalogPortResult<UndoDecisionV1Response> {
        let mut state = self.state.borrow_mut();
        Self::require_revision(&state, request.expected_catalog_revision)?;
        if state.undone.contains(&request.decision_id) {
            return Err(CatalogPortError::new(CatalogPortErrorKind::InvalidState));
        }
        let target = state
            .decisions
            .iter()
            .find(|decision| decision.decision_id == request.decision_id)
            .cloned()
            .ok_or_else(|| CatalogPortError::new(CatalogPortErrorKind::NotFound))?;
        let current_items = state.items.clone();
        let mut affected_item_ids = current_items
            .keys()
            .chain(target.before_items.keys())
            .copied()
            .collect::<Vec<_>>();
        affected_item_ids.sort_unstable();
        affected_item_ids.dedup();
        let affected_evidence_ids = current_items
            .values()
            .chain(target.before_items.values())
            .flat_map(|item| item.evidence_ids.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let decision = Self::decision(
            DecisionKindV1::Undo,
            affected_item_ids,
            affected_evidence_ids,
            Some(request.decision_id),
        );
        state.items = target.before_items;
        state.revision += 1;
        state.undone.insert(request.decision_id);
        state.decisions.push(StoredDecision {
            decision_id: decision.decision_id,
            before_items: current_items,
        });
        Ok(UndoDecisionV1Response {
            schema_version: 1,
            request_id: request.request_id,
            restored_items: state.items.values().cloned().collect(),
            decision,
            new_catalog_revision: state.revision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn preview_deletion(
        &self,
        request: &PreviewDeletionV1Request,
    ) -> CatalogPortResult<PreviewDeletionV1Response> {
        use DeletionDependencyClassV1::*;
        let classes = [
            Originals,
            Derivatives,
            SourceRecords,
            EvidenceRecords,
            DecisionRecords,
            RemoteReferences,
            RetainedSharedBlobs,
        ];
        Ok(PreviewDeletionV1Response {
            schema_version: 1,
            request_id: request.request_id,
            preview_snapshot_token: DeletionSnapshotTokenV1::new("snapshot-1".to_owned()).unwrap(),
            plan_sha256: Sha256Digest::parse("a".repeat(64)).unwrap(),
            prepared_at: "2026-07-15T16:00:00Z".to_owned(),
            expires_at: "2026-07-15T16:15:00Z".to_owned(),
            revisions: DeletionRevisionSnapshotV1 {
                catalog_revision: 1,
                evidence_generation: 1,
                receipt_revision: 1,
                photo_revision: 1,
                reconciliation_revision: 1,
                outfit_revision: 1,
                try_on_revision: 1,
                photokit_revision: 1,
            },
            counts: classes
                .into_iter()
                .map(|class| DeletionClassCountV1 {
                    class,
                    count: u64::from(matches!(class, Originals | RetainedSharedBlobs)),
                })
                .collect(),
            overall_count: 1,
            retained_shared_blob_count: 1,
            unique_blob_count: 1,
            unique_blob_bytes: 128,
            backup_retention: vec![],
            remote_retention: vec![],
            first_class: Originals,
            first_page: vec![DeletionPlanItemV1 {
                class: Originals,
                record_id: request.target_id.clone(),
                display_label: "Original image".to_owned(),
                retained: false,
            }],
            next_cursor: None,
        })
    }

    fn list_deletion_plan_items(
        &self,
        request: &ListDeletionPlanItemsV1Request,
    ) -> CatalogPortResult<ListDeletionPlanItemsV1Response> {
        Ok(ListDeletionPlanItemsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            preview_snapshot_token: request.preview_snapshot_token.clone(),
            class: request.class,
            items: vec![],
            total_count: 0,
            next_cursor: None,
        })
    }
}

fn attributes(name: &str) -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: name.to_owned(),
        category: ItemCategoryV1::Top,
        subcategory: None,
        brand: None,
        primary_color: None,
        size: None,
        notes: None,
        tags: vec![],
    }
}

fn save_request(
    name: &str,
    evidence_ids: Vec<EvidenceId>,
    expected_catalog_revision: u64,
) -> SaveItemV1Request {
    SaveItemV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        item_id: None,
        attributes: attributes(name),
        evidence_ids,
        expected_catalog_revision,
    }
}

#[test]
fn imports_advance_evidence_generation_without_advancing_catalog_revision() {
    let catalog = MemoryCatalog::default();
    let service = ApplicationService::new(catalog.clone(), (), ());

    let imported = service
        .import_local_sources_v1(ImportLocalSourcesV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            paths: vec!["/tmp/synthetic".to_owned()],
        })
        .unwrap();
    let listed = service
        .list_catalog_v1(ListCatalogV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            cursor: None,
            limit: 25,
        })
        .unwrap();

    assert_eq!(imported.evidence_generation, 1);
    assert_eq!(listed.evidence_generation, 1);
    assert_eq!(listed.catalog_revision, 0);
}

#[test]
fn stale_catalog_cas_is_rejected_without_a_decision_or_projection_write() {
    let catalog = MemoryCatalog::default();
    let service = ApplicationService::new(catalog.clone(), (), ());
    service
        .save_item_v1(save_request("First", vec![], 0))
        .unwrap();

    let error = service
        .save_item_v1(save_request("Stale", vec![], 0))
        .unwrap_err();

    assert_eq!(error.code, ErrorCodeV1::RequestConflict);
    assert_eq!(error.user_action, UserActionKeyV1::RefreshCatalog);
    assert_eq!(catalog.revision(), 1);
    assert_eq!(catalog.decision_count(), 1);
}

#[test]
fn merge_split_and_undo_append_history_and_restore_projections() {
    let catalog = MemoryCatalog::default();
    let service = ApplicationService::new(catalog.clone(), (), ());
    let first_evidence = EvidenceId::new_v4();
    let second_evidence = EvidenceId::new_v4();
    let third_evidence = EvidenceId::new_v4();
    let first = service
        .save_item_v1(save_request(
            "First",
            vec![first_evidence, second_evidence],
            0,
        ))
        .unwrap();
    let second = service
        .save_item_v1(save_request("Second", vec![third_evidence], 1))
        .unwrap();

    let merged = service
        .merge_items_v1(MergeItemsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            item_ids: vec![first.item.item_id, second.item.item_id],
            target_attributes: attributes("Merged"),
            expected_catalog_revision: 2,
        })
        .unwrap();
    assert_eq!(merged.item.evidence_ids.len(), 3);
    assert_eq!(catalog.decision_count(), 3);

    let merge_undo = service
        .undo_decision_v1(UndoDecisionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            decision_id: merged.decision.decision_id,
            expected_catalog_revision: 3,
        })
        .unwrap();
    assert_eq!(merge_undo.restored_items.len(), 2);
    assert_eq!(
        merge_undo.decision.compensates_decision_id,
        Some(merged.decision.decision_id)
    );
    assert_eq!(catalog.decision_count(), 4);

    let split = service
        .split_item_v1(SplitItemV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            item_id: first.item.item_id,
            groups: vec![
                SplitGroupV1 {
                    attributes: attributes("A"),
                    evidence_ids: vec![first_evidence],
                },
                SplitGroupV1 {
                    attributes: attributes("B"),
                    evidence_ids: vec![second_evidence],
                },
            ],
            expected_catalog_revision: 4,
        })
        .unwrap();
    assert_eq!(split.items.len(), 2);

    let split_undo = service
        .undo_decision_v1(UndoDecisionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            decision_id: split.decision.decision_id,
            expected_catalog_revision: 5,
        })
        .unwrap();
    assert_eq!(split_undo.restored_items.len(), 2);
    assert_eq!(catalog.decision_count(), 6);
}

#[test]
fn catalog_pages_and_deletion_preview_are_complete_contracts() {
    let catalog = MemoryCatalog::default();
    let service = ApplicationService::new(catalog, (), ());
    service
        .save_item_v1(save_request("First", vec![], 0))
        .unwrap();
    service
        .save_item_v1(save_request("Second", vec![], 1))
        .unwrap();

    let page = service
        .list_catalog_v1(ListCatalogV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            cursor: None,
            limit: 1,
        })
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.total_count, 2);
    assert!(page.next_cursor.is_some());

    let preview = service
        .preview_deletion_v1(PreviewDeletionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            target_kind: DeletionTargetKindV1::Item,
            target_id: page.items[0].item_id.to_string(),
            limit: 25,
        })
        .unwrap();
    assert_eq!(preview.counts.len(), 7);
    assert_eq!(preview.overall_count, 1);
    assert_eq!(preview.retained_shared_blob_count, 1);

    let plan_page = service
        .list_deletion_plan_items_v1(ListDeletionPlanItemsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            preview_snapshot_token: preview.preview_snapshot_token.clone(),
            class: DeletionDependencyClassV1::RemoteReferences,
            cursor: None,
            limit: 25,
        })
        .unwrap();
    assert_eq!(
        plan_page.preview_snapshot_token,
        preview.preview_snapshot_token
    );
}

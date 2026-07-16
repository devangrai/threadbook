use crate::backup_repository::{format_timestamp, lock_maintenance};
use crate::database::stable_id;
use crate::deletion_repository::prepare_plan;
use crate::photo_repository::augment_photo_deletion_closure;
use crate::receipt_repository::augment_receipt_image_deletion_closure;
use crate::reconciliation_repository::augment_reconciliation_deletion_closure;
use crate::{Database, PlatformError, PlatformResult};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use wardrobe_core::{
    CatalogItemV1, CatalogPort, CatalogPortError, CatalogPortErrorKind, CatalogPortResult,
    DecideEvidenceV1Request, DecideEvidenceV1Response, DecisionId, DecisionKindV1,
    DecisionSnapshotV1, DeletionClassCountV1, DeletionDependencyClassV1, DeletionPlanItemV1,
    DeletionSnapshotTokenV1, DeletionTargetKindV1, EvidenceDecisionActionV1, EvidenceId,
    EvidenceKindV1, EvidenceSnapshotV1, EvidenceStateV1, ImportLocalSourcesV1Request,
    ImportLocalSourcesV1Response, ImportRootId, ImportSourceKindV1, InboxStateV1, ItemAttributesV1,
    ItemId, ListCatalogV1Request, ListCatalogV1Response, ListDeletionPlanItemsV1Request,
    ListDeletionPlanItemsV1Response, ListInboxV1Request, ListInboxV1Response, MergeItemsV1Request,
    MergeItemsV1Response, PageCursorV1, PreviewDeletionV1Request, PreviewDeletionV1Response,
    QuarantineId, QuarantineSnapshotV1, RefreshImportRootsV1Request, RefreshImportRootsV1Response,
    ReplayStatusV1, SaveItemV1Request, SaveItemV1Response, SourceAvailabilityV1, SourceSnapshotV1,
    SplitItemV1Request, SplitItemV1Response, UndoDecisionV1Request, UndoDecisionV1Response,
    SCHEMA_VERSION_V1,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredItem {
    item_id: String,
    attributes: ItemAttributesV1,
    active: bool,
    created_revision: u64,
    updated_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredEvidence {
    evidence_id: String,
    state: String,
    assigned_item_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ProjectionSnapshot {
    affected_item_ids: Vec<String>,
    items: Vec<StoredItem>,
    evidence: Vec<StoredEvidence>,
}

impl CatalogPort for Database {
    fn import_local_sources(
        &self,
        request: &ImportLocalSourcesV1Request,
    ) -> CatalogPortResult<ImportLocalSourcesV1Response> {
        self.import_local(request).map_err(port_error)
    }

    fn refresh_import_roots(
        &self,
        request: &RefreshImportRootsV1Request,
    ) -> CatalogPortResult<RefreshImportRootsV1Response> {
        self.refresh_roots(request).map_err(port_error)
    }

    fn list_catalog(
        &self,
        request: &ListCatalogV1Request,
    ) -> CatalogPortResult<ListCatalogV1Response> {
        self.list_catalog_impl(request).map_err(port_error)
    }

    fn list_inbox(&self, request: &ListInboxV1Request) -> CatalogPortResult<ListInboxV1Response> {
        self.list_inbox_impl(request).map_err(port_error)
    }

    fn save_item_and_append_decision(
        &self,
        request: &SaveItemV1Request,
    ) -> CatalogPortResult<SaveItemV1Response> {
        self.save_item_impl(request).map_err(port_error)
    }

    fn decide_evidence_and_append_decision(
        &self,
        request: &DecideEvidenceV1Request,
    ) -> CatalogPortResult<DecideEvidenceV1Response> {
        self.decide_evidence_impl(request).map_err(port_error)
    }

    fn merge_items_and_append_decision(
        &self,
        request: &MergeItemsV1Request,
    ) -> CatalogPortResult<MergeItemsV1Response> {
        self.merge_items_impl(request).map_err(port_error)
    }

    fn split_item_and_append_decision(
        &self,
        request: &SplitItemV1Request,
    ) -> CatalogPortResult<SplitItemV1Response> {
        self.split_item_impl(request).map_err(port_error)
    }

    fn append_compensating_undo(
        &self,
        request: &UndoDecisionV1Request,
    ) -> CatalogPortResult<UndoDecisionV1Response> {
        self.undo_impl(request).map_err(port_error)
    }

    fn preview_deletion(
        &self,
        request: &PreviewDeletionV1Request,
    ) -> CatalogPortResult<PreviewDeletionV1Response> {
        self.preview_deletion_impl(request).map_err(port_error)
    }

    fn list_deletion_plan_items(
        &self,
        request: &ListDeletionPlanItemsV1Request,
    ) -> CatalogPortResult<ListDeletionPlanItemsV1Response> {
        self.list_deletion_items_impl(request).map_err(port_error)
    }
}

impl Database {
    fn list_catalog_impl(
        &self,
        request: &ListCatalogV1Request,
    ) -> PlatformResult<ListCatalogV1Response> {
        let connection = self.connection()?;
        let (catalog_revision, evidence_generation) = revisions(&connection)?;
        let offset = parse_cursor(
            request.cursor.as_ref(),
            "catalog",
            catalog_revision,
            evidence_generation,
        )?;
        let total_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM catalog_items WHERE active = 1",
            [],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT item_id FROM catalog_items WHERE active = 1
             ORDER BY display_name COLLATE NOCASE, item_id LIMIT ?1 OFFSET ?2",
        )?;
        let ids = statement
            .query_map(params![i64::from(request.limit), offset as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let items = ids
            .iter()
            .map(|item_id| load_catalog_item(&connection, item_id))
            .collect::<PlatformResult<Vec<_>>>()?;
        let next_offset = offset + items.len() as u64;
        let next_cursor = if next_offset < total_count as u64 {
            Some(make_cursor(
                "catalog",
                catalog_revision,
                evidence_generation,
                next_offset,
            )?)
        } else {
            None
        };
        Ok(ListCatalogV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            items,
            total_count: total_count as u64,
            catalog_revision,
            evidence_generation,
            next_cursor,
        })
    }

    fn list_inbox_impl(&self, request: &ListInboxV1Request) -> PlatformResult<ListInboxV1Response> {
        let connection = self.connection()?;
        let (catalog_revision, evidence_generation) = revisions(&connection)?;
        let cursor_kind = match request.state {
            InboxStateV1::Unresolved => "inbox-unresolved",
            InboxStateV1::Deferred => "inbox-deferred",
            InboxStateV1::Quarantine => "inbox-quarantine",
        };
        let offset = parse_cursor(
            request.cursor.as_ref(),
            cursor_kind,
            catalog_revision,
            evidence_generation,
        )?;
        let (evidence, quarantines, total_count) = match request.state {
            InboxStateV1::Unresolved | InboxStateV1::Deferred => {
                let state = if request.state == InboxStateV1::Unresolved {
                    "unresolved"
                } else {
                    "deferred"
                };
                let total: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM evidence WHERE state = ?1",
                    [state],
                    |row| row.get(0),
                )?;
                let mut statement = connection.prepare(
                    "SELECT evidence_id FROM evidence WHERE state = ?1
                     ORDER BY created_at_ms, evidence_id LIMIT ?2 OFFSET ?3",
                )?;
                let ids = statement
                    .query_map(
                        params![state, i64::from(request.limit), offset as i64],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                let rows = ids
                    .iter()
                    .map(|id| load_evidence(&connection, id))
                    .collect::<PlatformResult<Vec<_>>>()?;
                (rows, Vec::new(), total as u64)
            }
            InboxStateV1::Quarantine => {
                let total: i64 =
                    connection.query_row("SELECT COUNT(*) FROM quarantine_records", [], |row| {
                        row.get(0)
                    })?;
                let mut statement = connection.prepare(
                    "SELECT q.quarantine_id, q.source_id, q.reason_code,
                            s.blob_sha256, s.no_blob_reason
                     FROM quarantine_records q JOIN local_sources s ON s.source_id = q.source_id
                     ORDER BY q.created_at_ms, q.quarantine_id LIMIT ?1 OFFSET ?2",
                )?;
                let rows = statement
                    .query_map(params![i64::from(request.limit), offset as i64], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|(quarantine_id, source_id, code, blob, no_blob_reason)| {
                        Ok(QuarantineSnapshotV1 {
                            quarantine_id: parse_quarantine_id(&quarantine_id)?,
                            source: load_source(&connection, &source_id)?,
                            code,
                            raw_blob_preserved: blob.is_some(),
                            no_blob_reason,
                        })
                    })
                    .collect::<PlatformResult<Vec<_>>>()?;
                (Vec::new(), rows, total as u64)
            }
        };
        let next_offset = offset + evidence.len().max(quarantines.len()) as u64;
        let next_cursor = if next_offset < total_count {
            Some(make_cursor(
                cursor_kind,
                catalog_revision,
                evidence_generation,
                next_offset,
            )?)
        } else {
            None
        };
        Ok(ListInboxV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            evidence,
            quarantines,
            total_count,
            catalog_revision,
            evidence_generation,
            next_cursor,
        })
    }

    fn save_item_impl(&self, request: &SaveItemV1Request) -> PlatformResult<SaveItemV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, SaveItemV1Response>(&transaction, "save_item_v1", request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let item_id = request
            .item_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| stable_id("item", &request.request_id.to_string()));
        let mut evidence_ids = request
            .evidence_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        evidence_ids.extend(item_evidence_ids(&transaction, &item_id)?);
        evidence_ids.sort();
        evidence_ids.dedup();
        let inverse =
            capture_projection(&transaction, std::slice::from_ref(&item_id), &evidence_ids)?;
        ensure_assignable(&transaction, &request.evidence_ids, Some(&item_id))?;
        let revision = advance_revision(&transaction, request.expected_catalog_revision)?;
        upsert_item(&transaction, &item_id, &request.attributes, revision)?;
        set_item_evidence(&transaction, &item_id, &request.evidence_ids, revision)?;
        let decision = append_decision(
            &transaction,
            &request.request_id.to_string(),
            "save",
            revision,
            request,
            &inverse,
            None,
            std::slice::from_ref(&item_id),
            &request
                .evidence_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )?;
        let item = load_catalog_item(&transaction, &item_id)?;
        let response = SaveItemV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            item,
            decision,
            new_catalog_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(&transaction, "save_item_v1", request, &response)?;
        transaction.commit()?;
        Ok(response)
    }

    fn decide_evidence_impl(
        &self,
        request: &DecideEvidenceV1Request,
    ) -> PlatformResult<DecideEvidenceV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, DecideEvidenceV1Response>(&transaction, "decide_evidence_v1", request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let evidence_id = request.evidence_id.to_string();
        let current_item: Option<String> = transaction
            .query_row(
                "SELECT item_id FROM item_evidence WHERE evidence_id = ?1",
                [&evidence_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut item_ids = current_item.into_iter().collect::<Vec<_>>();
        if let Some(item_id) = request.item_id {
            item_ids.push(item_id.to_string());
        }
        item_ids.sort();
        item_ids.dedup();
        let inverse =
            capture_projection(&transaction, &item_ids, std::slice::from_ref(&evidence_id))?;
        let revision = advance_revision(&transaction, request.expected_catalog_revision)?;
        delete_item_evidence_by_evidence(&transaction, &evidence_id)?;
        let state = match request.action {
            EvidenceDecisionActionV1::Assign => {
                let item_id = request
                    .item_id
                    .ok_or(PlatformError::InvalidInput("item_id"))?
                    .to_string();
                require_active_item(&transaction, &item_id)?;
                transaction.execute(
                    "INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
                     VALUES (?1, ?2, ?3)",
                    params![item_id, evidence_id, revision as i64],
                )?;
                "assigned"
            }
            EvidenceDecisionActionV1::Reject => "rejected",
            EvidenceDecisionActionV1::Defer => "deferred",
        };
        let changed = transaction.execute(
            "UPDATE evidence SET state = ?2, updated_at_ms = ?3 WHERE evidence_id = ?1",
            params![evidence_id, state, unix_now_ms()?],
        )?;
        if changed != 1 {
            return Err(PlatformError::InvalidInput("evidence_id"));
        }
        let decision = append_decision(
            &transaction,
            &request.request_id.to_string(),
            match request.action {
                EvidenceDecisionActionV1::Assign => "assign",
                EvidenceDecisionActionV1::Reject => "reject",
                EvidenceDecisionActionV1::Defer => "defer",
            },
            revision,
            request,
            &inverse,
            None,
            &item_ids,
            std::slice::from_ref(&evidence_id),
        )?;
        let evidence = load_evidence(&transaction, &evidence_id)?;
        let response = DecideEvidenceV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            evidence,
            decision,
            new_catalog_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(&transaction, "decide_evidence_v1", request, &response)?;
        transaction.commit()?;
        Ok(response)
    }

    fn merge_items_impl(
        &self,
        request: &MergeItemsV1Request,
    ) -> PlatformResult<MergeItemsV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, MergeItemsV1Response>(&transaction, "merge_items_v1", request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let item_ids = request
            .item_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        for item_id in &item_ids {
            require_active_item(&transaction, item_id)?;
        }
        let evidence_ids = evidence_for_items(&transaction, &item_ids)?;
        let inverse = capture_projection(&transaction, &item_ids, &evidence_ids)?;
        let revision = advance_revision(&transaction, request.expected_catalog_revision)?;
        let target = &item_ids[0];
        upsert_item(&transaction, target, &request.target_attributes, revision)?;
        for source in &item_ids[1..] {
            transaction.execute(
                "UPDATE catalog_items SET active = 0, updated_revision = ?2 WHERE item_id = ?1",
                params![source, revision as i64],
            )?;
        }
        for source in &item_ids {
            transaction.execute(
                "UPDATE item_evidence SET item_id = ?1, assigned_revision = ?2
                 WHERE item_id = ?3",
                params![target, revision as i64, source],
            )?;
        }
        let decision = append_decision(
            &transaction,
            &request.request_id.to_string(),
            "merge",
            revision,
            request,
            &inverse,
            None,
            &item_ids,
            &evidence_ids,
        )?;
        let item = load_catalog_item(&transaction, target)?;
        let response = MergeItemsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            item,
            decision,
            new_catalog_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(&transaction, "merge_items_v1", request, &response)?;
        transaction.commit()?;
        Ok(response)
    }

    fn split_item_impl(&self, request: &SplitItemV1Request) -> PlatformResult<SplitItemV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, SplitItemV1Response>(&transaction, "split_item_v1", request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let source_id = request.item_id.to_string();
        require_active_item(&transaction, &source_id)?;
        let existing = item_evidence_ids(&transaction, &source_id)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let requested = request
            .groups
            .iter()
            .flat_map(|group| group.evidence_ids.iter().map(ToString::to_string))
            .collect::<BTreeSet<_>>();
        if existing != requested {
            return Err(PlatformError::InvalidInput("split_evidence_partition"));
        }
        let mut item_ids = vec![source_id.clone()];
        item_ids.extend(
            (1..request.groups.len())
                .map(|index| stable_id("split-item", &format!("{}:{index}", request.request_id))),
        );
        let inverse = capture_projection(
            &transaction,
            &item_ids,
            &requested.iter().cloned().collect::<Vec<_>>(),
        )?;
        let revision = advance_revision(&transaction, request.expected_catalog_revision)?;
        delete_item_evidence_by_item(&transaction, &source_id)?;
        for ((item_id, group), index) in item_ids.iter().zip(&request.groups).zip(0..) {
            upsert_item(&transaction, item_id, &group.attributes, revision)?;
            for evidence_id in &group.evidence_ids {
                transaction.execute(
                    "INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
                     VALUES (?1, ?2, ?3)",
                    params![item_id, evidence_id.to_string(), revision as i64],
                )?;
            }
            if index > 0 {
                transaction.execute(
                    "UPDATE catalog_items SET active = 1 WHERE item_id = ?1",
                    [item_id],
                )?;
            }
        }
        let evidence_ids = requested.into_iter().collect::<Vec<_>>();
        let decision = append_decision(
            &transaction,
            &request.request_id.to_string(),
            "split",
            revision,
            request,
            &inverse,
            None,
            &item_ids,
            &evidence_ids,
        )?;
        let items = item_ids
            .iter()
            .map(|item_id| load_catalog_item(&transaction, item_id))
            .collect::<PlatformResult<Vec<_>>>()?;
        let response = SplitItemV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            items,
            decision,
            new_catalog_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(&transaction, "split_item_v1", request, &response)?;
        transaction.commit()?;
        Ok(response)
    }

    fn undo_impl(&self, request: &UndoDecisionV1Request) -> PlatformResult<UndoDecisionV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, UndoDecisionV1Response>(&transaction, "undo_decision_v1", request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let target_id = request.decision_id.to_string();
        let (target_revision, inverse_json): (i64, String) = transaction
            .query_row(
                "SELECT catalog_revision, inverse_json FROM catalog_decisions
                 WHERE decision_id = ?1",
                [&target_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("decision_id"))?;
        if target_revision as u64 != request.expected_catalog_revision {
            return Err(PlatformError::Conflict("undo_non_head"));
        }
        let compensated = transaction
            .query_row(
                "SELECT 1 FROM catalog_decisions WHERE compensates_decision_id = ?1",
                [&target_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if compensated {
            return Err(PlatformError::Conflict("decision_already_compensated"));
        }
        let target_snapshot: ProjectionSnapshot = serde_json::from_str(&inverse_json)?;
        let evidence_ids = target_snapshot
            .evidence
            .iter()
            .map(|value| value.evidence_id.clone())
            .collect::<Vec<_>>();
        let current = capture_projection(
            &transaction,
            &target_snapshot.affected_item_ids,
            &evidence_ids,
        )?;
        let revision = advance_revision(&transaction, request.expected_catalog_revision)?;
        restore_projection(&transaction, &target_snapshot, revision)?;
        let decision = append_decision(
            &transaction,
            &request.request_id.to_string(),
            "undo",
            revision,
            request,
            &current,
            Some(&target_id),
            &target_snapshot.affected_item_ids,
            &evidence_ids,
        )?;
        let mut restored_items = Vec::new();
        for item_id in &target_snapshot.affected_item_ids {
            let active = transaction
                .query_row(
                    "SELECT active FROM catalog_items WHERE item_id = ?1",
                    [item_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if active == Some(1) {
                restored_items.push(load_catalog_item(&transaction, item_id)?);
            }
        }
        let response = UndoDecisionV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            restored_items,
            decision,
            new_catalog_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(&transaction, "undo_decision_v1", request, &response)?;
        transaction.commit()?;
        Ok(response)
    }

    fn preview_deletion_impl(
        &self,
        request: &PreviewDeletionV1Request,
    ) -> PlatformResult<PreviewDeletionV1Response> {
        let now_ms = unix_now_ms()?;
        let maintenance = lock_maintenance()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (catalog_revision, evidence_generation) = revisions(&transaction)?;
        let (
            photo_revision,
            reconciliation_revision,
            outfit_revision,
            try_on_revision,
            photokit_revision,
        ): (i64, i64, i64, i64, i64) = transaction.query_row(
            "SELECT photo_revision, reconciliation_revision, outfit_revision,
                    try_on_revision, photokit_revision
             FROM revision_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        require_deletion_target(&transaction, request.target_kind, &request.target_id)?;
        let token_text = stable_id(
            "deletion-preview",
            &format!("{}:{}", request.request_id, request.target_id),
        );
        transaction.execute(
            "INSERT OR IGNORE INTO deletion_previews(
                snapshot_token, target_kind, target_id, catalog_revision,
                evidence_generation, photo_revision, reconciliation_revision,
                outfit_revision, try_on_revision, photokit_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                token_text,
                deletion_target_db(request.target_kind),
                request.target_id,
                catalog_revision as i64,
                evidence_generation as i64,
                photo_revision,
                reconciliation_revision as i64,
                outfit_revision,
                try_on_revision,
                photokit_revision,
                now_ms
            ],
        )?;
        materialize_deletion_rows(
            &transaction,
            &token_text,
            request.target_kind,
            &request.target_id,
        )?;
        let prepared = prepare_plan(
            &transaction,
            &self.paths,
            &maintenance,
            &token_text,
            request.target_kind,
            &request.target_id,
            now_ms,
        )?;
        let counts = deletion_counts(&transaction, &token_text)?;
        let first_class = DeletionDependencyClassV1::Originals;
        let (first_page, next_cursor, _) =
            deletion_page(&transaction, &token_text, first_class, 0, request.limit)?;
        let overall_count = counts
            .iter()
            .filter(|count| count.class != DeletionDependencyClassV1::RetainedSharedBlobs)
            .map(|count| count.count)
            .sum();
        let retained_shared_blob_count = counts
            .iter()
            .find(|count| count.class == DeletionDependencyClassV1::RetainedSharedBlobs)
            .map(|count| count.count)
            .unwrap_or(0);
        transaction.commit()?;
        Ok(PreviewDeletionV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            preview_snapshot_token: make_snapshot_token(&token_text)?,
            plan_sha256: prepared.plan_sha256,
            prepared_at: format_timestamp(prepared.prepared_at_ms)?,
            expires_at: format_timestamp(prepared.expires_at_ms)?,
            revisions: prepared.revisions,
            counts,
            overall_count,
            retained_shared_blob_count,
            unique_blob_count: prepared.unique_blob_count,
            unique_blob_bytes: prepared.unique_blob_bytes,
            backup_retention: prepared.backup_retention,
            remote_retention: prepared.remote_retention,
            first_class,
            first_page,
            next_cursor,
        })
    }

    fn list_deletion_items_impl(
        &self,
        request: &ListDeletionPlanItemsV1Request,
    ) -> PlatformResult<ListDeletionPlanItemsV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let token = request.preview_snapshot_token.as_str();
        let preview_revisions = transaction
            .query_row(
                "SELECT plan.catalog_revision, plan.evidence_generation, plan.receipt_revision,
                        plan.photo_revision, plan.reconciliation_revision,
                        plan.outfit_revision, plan.try_on_revision,
                        plan.photokit_revision
                 FROM deletion_plans plan WHERE plan.snapshot_token = ?1",
                [token],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("snapshot_token"))?;
        let current_revisions: (i64, i64, i64, i64, i64, i64, i64, i64) = transaction.query_row(
            "SELECT catalog_revision, evidence_generation, receipt_revision, photo_revision,
                    reconciliation_revision, outfit_revision, try_on_revision,
                    photokit_revision
             FROM revision_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?;
        if preview_revisions != current_revisions {
            return Err(PlatformError::Conflict("snapshot_expired"));
        }
        let offset = parse_deletion_cursor(request.cursor.as_ref(), token, request.class)?;
        let (items, next_cursor, total_count) =
            deletion_page(&transaction, token, request.class, offset, request.limit)?;
        let response = ListDeletionPlanItemsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            preview_snapshot_token: request.preview_snapshot_token.clone(),
            class: request.class,
            items,
            total_count,
            next_cursor,
        };
        transaction.commit()?;
        Ok(response)
    }
}

fn advance_revision(transaction: &Transaction<'_>, expected: u64) -> PlatformResult<u64> {
    let next: Option<i64> = transaction
        .query_row(
            "UPDATE revision_state SET catalog_revision = catalog_revision + 1
             WHERE singleton = 1 AND catalog_revision = ?1 RETURNING catalog_revision",
            [expected as i64],
            |row| row.get(0),
        )
        .optional()?;
    next.map(|value| value as u64)
        .ok_or(PlatformError::Conflict("catalog_revision"))
}

fn upsert_item(
    transaction: &Transaction<'_>,
    item_id: &str,
    attributes: &ItemAttributesV1,
    revision: u64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO catalog_items(
            item_id, display_name, attributes_json, active, created_revision, updated_revision
         ) VALUES (?1, ?2, ?3, 1, ?4, ?4)
         ON CONFLICT(item_id) DO UPDATE SET display_name = excluded.display_name,
            attributes_json = excluded.attributes_json, active = 1,
            updated_revision = excluded.updated_revision",
        params![
            item_id,
            attributes.display_name,
            serde_json::to_string(attributes)?,
            revision as i64
        ],
    )?;
    Ok(())
}

fn delete_item_evidence_by_item(
    transaction: &Transaction<'_>,
    item_id: &str,
) -> PlatformResult<()> {
    let authorized = transaction.execute(
        "INSERT INTO domain_mutation_authority(entity_kind,key_json)
         SELECT 'item_evidence',json_array(item_id,evidence_id)
         FROM item_evidence WHERE item_id=?1",
        [item_id],
    )?;
    let deleted = transaction.execute("DELETE FROM item_evidence WHERE item_id=?1", [item_id])?;
    let cleared = transaction.execute(
        "DELETE FROM domain_mutation_authority WHERE entity_kind='item_evidence'",
        [],
    )?;
    if authorized != deleted || cleared != authorized {
        return Err(PlatformError::Corrupt("item_evidence_mutation_authority"));
    }
    Ok(())
}

fn delete_item_evidence_by_evidence(
    transaction: &Transaction<'_>,
    evidence_id: &str,
) -> PlatformResult<()> {
    let authorized = transaction.execute(
        "INSERT INTO domain_mutation_authority(entity_kind,key_json)
         SELECT 'item_evidence',json_array(item_id,evidence_id)
         FROM item_evidence WHERE evidence_id=?1",
        [evidence_id],
    )?;
    let deleted = transaction.execute(
        "DELETE FROM item_evidence WHERE evidence_id=?1",
        [evidence_id],
    )?;
    let cleared = transaction.execute(
        "DELETE FROM domain_mutation_authority WHERE entity_kind='item_evidence'",
        [],
    )?;
    if authorized != deleted || cleared != authorized {
        return Err(PlatformError::Corrupt("item_evidence_mutation_authority"));
    }
    Ok(())
}

fn set_item_evidence(
    transaction: &Transaction<'_>,
    item_id: &str,
    evidence_ids: &[EvidenceId],
    revision: u64,
) -> PlatformResult<()> {
    let previous = item_evidence_ids(transaction, item_id)?;
    delete_item_evidence_by_item(transaction, item_id)?;
    for evidence_id in previous {
        transaction.execute(
            "UPDATE evidence SET state = 'unresolved' WHERE evidence_id = ?1",
            [evidence_id],
        )?;
    }
    for evidence_id in evidence_ids {
        transaction.execute(
            "INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
             VALUES (?1, ?2, ?3)",
            params![item_id, evidence_id.to_string(), revision as i64],
        )?;
        transaction.execute(
            "UPDATE evidence SET state = 'assigned' WHERE evidence_id = ?1",
            [evidence_id.to_string()],
        )?;
    }
    Ok(())
}

fn ensure_assignable(
    transaction: &Transaction<'_>,
    evidence_ids: &[EvidenceId],
    target_item: Option<&str>,
) -> PlatformResult<()> {
    for evidence_id in evidence_ids {
        let row: Option<Option<String>> = transaction
            .query_row(
                "SELECT ie.item_id FROM evidence e
                 LEFT JOIN item_evidence ie ON ie.evidence_id = e.evidence_id
                 WHERE e.evidence_id = ?1",
                [evidence_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        match row {
            None => return Err(PlatformError::InvalidInput("evidence_id")),
            Some(Some(item)) if Some(item.as_str()) != target_item => {
                return Err(PlatformError::Conflict("evidence_already_assigned"))
            }
            _ => {}
        }
    }
    Ok(())
}

fn capture_projection(
    connection: &Connection,
    item_ids: &[String],
    evidence_ids: &[String],
) -> PlatformResult<ProjectionSnapshot> {
    let mut items = Vec::new();
    for item_id in item_ids {
        if let Some(row) = connection
            .query_row(
                "SELECT attributes_json, active, created_revision, updated_revision
                 FROM catalog_items WHERE item_id = ?1",
                [item_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
        {
            items.push(StoredItem {
                item_id: item_id.clone(),
                attributes: serde_json::from_str(&row.0)?,
                active: row.1 == 1,
                created_revision: row.2 as u64,
                updated_revision: row.3 as u64,
            });
        }
    }
    let mut evidence = Vec::new();
    for evidence_id in evidence_ids {
        if let Some((state, item_id)) = connection
            .query_row(
                "SELECT e.state, ie.item_id FROM evidence e
                 LEFT JOIN item_evidence ie ON ie.evidence_id = e.evidence_id
                 WHERE e.evidence_id = ?1",
                [evidence_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
        {
            evidence.push(StoredEvidence {
                evidence_id: evidence_id.clone(),
                state,
                assigned_item_id: item_id,
            });
        }
    }
    Ok(ProjectionSnapshot {
        affected_item_ids: item_ids.to_vec(),
        items,
        evidence,
    })
}

fn restore_projection(
    transaction: &Transaction<'_>,
    snapshot: &ProjectionSnapshot,
    revision: u64,
) -> PlatformResult<()> {
    for item_id in &snapshot.affected_item_ids {
        delete_item_evidence_by_item(transaction, item_id)?;
        if !snapshot.items.iter().any(|item| &item.item_id == item_id) {
            transaction.execute(
                "UPDATE catalog_items SET active = 0, updated_revision = ?2 WHERE item_id = ?1",
                params![item_id, revision as i64],
            )?;
        }
    }
    for item in &snapshot.items {
        transaction.execute(
            "INSERT INTO catalog_items(
                item_id, display_name, attributes_json, active, created_revision, updated_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(item_id) DO UPDATE SET display_name = excluded.display_name,
                attributes_json = excluded.attributes_json, active = excluded.active,
                updated_revision = excluded.updated_revision",
            params![
                item.item_id,
                item.attributes.display_name,
                serde_json::to_string(&item.attributes)?,
                i64::from(item.active),
                item.created_revision as i64,
                revision as i64
            ],
        )?;
    }
    for evidence in &snapshot.evidence {
        delete_item_evidence_by_evidence(transaction, &evidence.evidence_id)?;
        transaction.execute(
            "UPDATE evidence SET state = ?2 WHERE evidence_id = ?1",
            params![evidence.evidence_id, evidence.state],
        )?;
        if let Some(item_id) = &evidence.assigned_item_id {
            transaction.execute(
                "INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
                 VALUES (?1, ?2, ?3)",
                params![item_id, evidence.evidence_id, revision as i64],
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_decision<Q: Serialize>(
    transaction: &Transaction<'_>,
    request_id: &str,
    kind: &str,
    revision: u64,
    forward: &Q,
    inverse: &ProjectionSnapshot,
    compensates: Option<&str>,
    item_ids: &[String],
    evidence_ids: &[String],
) -> PlatformResult<DecisionSnapshotV1> {
    let decision_id = stable_id("decision", request_id);
    transaction.execute(
        "INSERT INTO catalog_decisions(
            decision_id, request_id, decision_kind, catalog_revision,
            forward_json, inverse_json, compensates_decision_id, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            decision_id,
            request_id,
            kind,
            revision as i64,
            serde_json::to_string(forward)?,
            serde_json::to_string(inverse)?,
            compensates,
            unix_now_ms()?
        ],
    )?;
    for item_id in item_ids {
        transaction.execute(
            "INSERT INTO decision_entities(decision_id, entity_kind, entity_id)
             VALUES (?1, 'item', ?2)",
            params![decision_id, item_id],
        )?;
    }
    for evidence_id in evidence_ids {
        transaction.execute(
            "INSERT INTO decision_entities(decision_id, entity_kind, entity_id)
             VALUES (?1, 'evidence', ?2)",
            params![decision_id, evidence_id],
        )?;
    }
    Ok(DecisionSnapshotV1 {
        decision_id: parse_decision_id(&decision_id)?,
        kind: match kind {
            "save" => DecisionKindV1::SaveItem,
            "assign" | "reject" | "defer" => DecisionKindV1::DecideEvidence,
            "merge" => DecisionKindV1::MergeItems,
            "split" => DecisionKindV1::SplitItem,
            "undo" => DecisionKindV1::Undo,
            _ => return Err(PlatformError::Corrupt("decision_kind")),
        },
        affected_item_ids: item_ids
            .iter()
            .map(|value| parse_item_id(value))
            .collect::<PlatformResult<Vec<_>>>()?,
        affected_evidence_ids: evidence_ids
            .iter()
            .map(|value| parse_evidence_id(value))
            .collect::<PlatformResult<Vec<_>>>()?,
        compensates_decision_id: compensates.map(parse_decision_id).transpose()?,
        reversible: true,
    })
}

fn load_catalog_item(connection: &Connection, item_id: &str) -> PlatformResult<CatalogItemV1> {
    let attributes_json: String = connection
        .query_row(
            "SELECT attributes_json FROM catalog_items WHERE item_id = ?1 AND active = 1",
            [item_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("item_id"))?;
    let evidence_ids = item_evidence_ids(connection, item_id)?
        .iter()
        .map(|value| parse_evidence_id(value))
        .collect::<PlatformResult<Vec<_>>>()?;
    let decision_id: String = connection
        .query_row(
            "SELECT d.decision_id FROM catalog_decisions d
             JOIN decision_entities de ON de.decision_id = d.decision_id
             WHERE de.entity_kind = 'item' AND de.entity_id = ?1
             ORDER BY d.catalog_revision DESC LIMIT 1",
            [item_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(PlatformError::Corrupt("item_decision_missing"))?;
    Ok(CatalogItemV1 {
        item_id: parse_item_id(item_id)?,
        attributes: serde_json::from_str(&attributes_json)?,
        evidence_ids,
        last_decision_id: parse_decision_id(&decision_id)?,
    })
}

fn load_evidence(connection: &Connection, evidence_id: &str) -> PlatformResult<EvidenceSnapshotV1> {
    let row = connection
        .query_row(
            "SELECT e.source_id, e.evidence_kind, e.state, ie.item_id,
                    substr(s.canonical_locator, 1, 240)
             FROM evidence e JOIN local_sources s ON s.source_id = e.source_id
             LEFT JOIN item_evidence ie ON ie.evidence_id = e.evidence_id
             WHERE e.evidence_id = ?1",
            [evidence_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("evidence_id"))?;
    Ok(EvidenceSnapshotV1 {
        evidence_id: parse_evidence_id(evidence_id)?,
        source: load_source(connection, &row.0)?,
        kind: match row.1.as_str() {
            "image" => EvidenceKindV1::Image,
            "message_attachment" => EvidenceKindV1::MessageAttachment,
            _ => return Err(PlatformError::Corrupt("evidence_kind")),
        },
        state: match row.2.as_str() {
            "unresolved" => EvidenceStateV1::Unresolved,
            "deferred" => EvidenceStateV1::Deferred,
            "assigned" => EvidenceStateV1::Assigned,
            "rejected" => EvidenceStateV1::Rejected,
            _ => return Err(PlatformError::Corrupt("evidence_state")),
        },
        assigned_item_id: row.3.as_deref().map(parse_item_id).transpose()?,
        review_label: if row.4.is_empty() {
            "Imported evidence".to_owned()
        } else {
            row.4
        },
    })
}

fn load_source(connection: &Connection, source_id: &str) -> PlatformResult<SourceSnapshotV1> {
    let row = connection
        .query_row(
            "SELECT root_id, parent_source_id, source_kind, status,
                    substr(canonical_locator, 1, 240), raw_sha256
             FROM local_sources WHERE source_id = ?1",
            [source_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("source_id"))?;
    Ok(SourceSnapshotV1 {
        source_id: parse_source_id(source_id)?,
        import_root_id: row.0.as_deref().map(parse_import_root_id).transpose()?,
        parent_source_id: row.1.as_deref().map(parse_source_id).transpose()?,
        kind: match row.2.as_str() {
            "folder_image" => ImportSourceKindV1::ImageFile,
            "eml" => ImportSourceKindV1::EmlFile,
            "mbox" => ImportSourceKindV1::MboxFile,
            "mbox_message" => ImportSourceKindV1::MboxMessage,
            _ => return Err(PlatformError::Corrupt("source_kind")),
        },
        availability: match row.3.as_str() {
            "imported" => SourceAvailabilityV1::Present,
            "quarantined" => SourceAvailabilityV1::Quarantined,
            "missing" => SourceAvailabilityV1::Missing,
            "unavailable" => SourceAvailabilityV1::Unavailable,
            _ => return Err(PlatformError::Corrupt("source_availability")),
        },
        provenance_label: if row.4.is_empty() {
            "Imported source".to_owned()
        } else {
            row.4
        },
        raw_blob_sha256: row.5,
    })
}

fn item_evidence_ids(connection: &Connection, item_id: &str) -> PlatformResult<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT evidence_id FROM item_evidence WHERE item_id = ?1 ORDER BY evidence_id")?;
    let values = statement
        .query_map([item_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(values)
}

fn evidence_for_items(connection: &Connection, item_ids: &[String]) -> PlatformResult<Vec<String>> {
    let mut values = Vec::new();
    for item_id in item_ids {
        values.extend(item_evidence_ids(connection, item_id)?);
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn require_active_item(connection: &Connection, item_id: &str) -> PlatformResult<()> {
    connection
        .query_row(
            "SELECT 1 FROM catalog_items WHERE item_id = ?1 AND active = 1",
            [item_id],
            |_| Ok(()),
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("item_id"))
}

fn revisions(connection: &Connection) -> PlatformResult<(u64, u64)> {
    let values: (i64, i64) = connection.query_row(
        "SELECT catalog_revision, evidence_generation FROM revision_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((values.0 as u64, values.1 as u64))
}

fn make_cursor(
    kind: &str,
    catalog: u64,
    evidence: u64,
    offset: u64,
) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!("{kind}.{catalog}.{evidence}.{offset}"))
        .map_err(|_| PlatformError::Corrupt("cursor"))
}

fn parse_cursor(
    cursor: Option<&PageCursorV1>,
    kind: &str,
    catalog: u64,
    evidence: u64,
) -> PlatformResult<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let pieces = cursor.as_str().split('.').collect::<Vec<_>>();
    if pieces.len() != 4
        || pieces[0] != kind
        || pieces[1].parse::<u64>().ok() != Some(catalog)
        || pieces[2].parse::<u64>().ok() != Some(evidence)
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    pieces[3]
        .parse()
        .map_err(|_| PlatformError::InvalidInput("cursor"))
}

fn replay<Q: Serialize, R: DeserializeOwned>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
) -> PlatformResult<Option<R>> {
    let request_id = request_id_from_json(request)?;
    let envelope = envelope_hash(request)?;
    let row = transaction
        .query_row(
            "SELECT command_name, envelope_hash, response_json
             FROM command_receipts WHERE request_id = ?1",
            [&request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((stored_command, stored_envelope, response))
            if stored_command == command && stored_envelope == envelope =>
        {
            Ok(Some(serde_json::from_str(&response)?))
        }
        Some(_) => Err(PlatformError::Conflict("command_envelope_changed")),
        None => Ok(None),
    }
}

fn store_receipt<Q: Serialize, R: Serialize>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
    response: &R,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO command_receipts(
            request_id, command_name, envelope_hash, response_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            request_id_from_json(request)?,
            command,
            envelope_hash(request)?,
            serde_json::to_string(response)?,
            unix_now_ms()?
        ],
    )?;
    Ok(())
}

fn request_id_from_json<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    serde_json::to_value(request)?
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(PlatformError::Corrupt("request_id"))
}

fn envelope_hash<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(request)?)
    ))
}

fn deletion_classes() -> [DeletionDependencyClassV1; 7] {
    [
        DeletionDependencyClassV1::Originals,
        DeletionDependencyClassV1::Derivatives,
        DeletionDependencyClassV1::SourceRecords,
        DeletionDependencyClassV1::EvidenceRecords,
        DeletionDependencyClassV1::DecisionRecords,
        DeletionDependencyClassV1::RemoteReferences,
        DeletionDependencyClassV1::RetainedSharedBlobs,
    ]
}

fn deletion_class_db(class: DeletionDependencyClassV1) -> &'static str {
    match class {
        DeletionDependencyClassV1::Originals => "originals",
        DeletionDependencyClassV1::Derivatives => "derivatives",
        DeletionDependencyClassV1::SourceRecords => "source_records",
        DeletionDependencyClassV1::EvidenceRecords => "evidence_records",
        DeletionDependencyClassV1::DecisionRecords => "decision_records",
        DeletionDependencyClassV1::RemoteReferences => "remote_references",
        DeletionDependencyClassV1::RetainedSharedBlobs => "retained_shared_blobs",
    }
}

fn deletion_target_db(kind: DeletionTargetKindV1) -> &'static str {
    match kind {
        DeletionTargetKindV1::ImportRoot => "import_root",
        DeletionTargetKindV1::Source => "source",
        DeletionTargetKindV1::Item => "item",
        DeletionTargetKindV1::PhotoKitEnrollment => "photokit_enrollment",
        DeletionTargetKindV1::PhotoKitAsset => "photokit_asset",
    }
}

fn require_deletion_target(
    connection: &Connection,
    kind: DeletionTargetKindV1,
    id: &str,
) -> PlatformResult<()> {
    let sql = match kind {
        DeletionTargetKindV1::ImportRoot => "SELECT 1 FROM import_roots WHERE root_id = ?1",
        DeletionTargetKindV1::Source => "SELECT 1 FROM local_sources WHERE source_id = ?1",
        DeletionTargetKindV1::Item => "SELECT 1 FROM catalog_items WHERE item_id = ?1",
        DeletionTargetKindV1::PhotoKitEnrollment => {
            "SELECT 1 FROM photokit_enrollments WHERE enrollment_epoch = ?1"
        }
        DeletionTargetKindV1::PhotoKitAsset => "SELECT 1 FROM photokit_assets WHERE asset_id = ?1",
    };
    connection
        .query_row(sql, [id], |_| Ok(()))
        .optional()?
        .ok_or(PlatformError::InvalidInput("deletion_target"))
}

pub(crate) fn materialize_deletion_rows(
    transaction: &Transaction<'_>,
    token: &str,
    kind: DeletionTargetKindV1,
    target_id: &str,
) -> PlatformResult<()> {
    let mut source_ids = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    let mut item_ids = BTreeSet::new();
    match kind {
        DeletionTargetKindV1::Item => {
            item_ids.insert(target_id.to_owned());
        }
        DeletionTargetKindV1::Source => {
            source_ids.insert(target_id.to_owned());
        }
        DeletionTargetKindV1::ImportRoot => {
            let mut statement =
                transaction.prepare("SELECT source_id FROM local_sources WHERE root_id = ?1")?;
            source_ids.extend(
                statement
                    .query_map([target_id], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        DeletionTargetKindV1::PhotoKitEnrollment | DeletionTargetKindV1::PhotoKitAsset => {
            insert_preview_row(transaction, token, "source_records", target_id, target_id)?;
            if kind == DeletionTargetKindV1::PhotoKitEnrollment {
                let cleanup_id = format!("photokit_key_cleanup:{target_id}");
                insert_preview_row(
                    transaction,
                    token,
                    "decision_records",
                    &cleanup_id,
                    &cleanup_id,
                )?;
            }
            return Ok(());
        }
    }
    let gmail_provider_source_ids = expand_gmail_source_lineage(transaction, &mut source_ids)?;
    let receipt = expand_deletion_closure(
        transaction,
        &mut source_ids,
        &mut evidence_ids,
        &mut item_ids,
    )?;

    if kind == DeletionTargetKindV1::ImportRoot {
        insert_preview_row(transaction, token, "source_records", target_id, target_id)?;
        insert_related_rows(
            transaction,
            token,
            "source_records",
            "import_scans",
            "scan_id",
            "root_id",
            target_id,
        )?;
    }
    for item_id in &item_ids {
        insert_preview_row(transaction, token, "source_records", item_id, item_id)?;
    }
    for source_id in &source_ids {
        insert_preview_row(transaction, token, "source_records", source_id, source_id)?;
        insert_related_rows(
            transaction,
            token,
            "source_records",
            "source_provenance",
            "provenance_id",
            "source_id",
            source_id,
        )?;
        insert_related_rows(
            transaction,
            token,
            "source_records",
            "quarantine_records",
            "quarantine_id",
            "source_id",
            source_id,
        )?;
        insert_related_rows(
            transaction,
            token,
            "evidence_records",
            "mime_parts",
            "part_id",
            "source_id",
            source_id,
        )?;
        insert_related_rows(
            transaction,
            token,
            "derivatives",
            "derivatives",
            "derivative_id",
            "source_id",
            source_id,
        )?;
        insert_related_rows(
            transaction,
            token,
            "remote_references",
            "remote_references",
            "remote_reference_id",
            "source_id",
            source_id,
        )?;
    }
    materialize_gmail_lineage_rows(transaction, token, &gmail_provider_source_ids)?;
    for evidence_id in &evidence_ids {
        insert_preview_row(
            transaction,
            token,
            "evidence_records",
            evidence_id,
            evidence_id,
        )?;
        if let Some(item_id) = transaction
            .query_row(
                "SELECT item_id FROM item_evidence WHERE evidence_id = ?1",
                [evidence_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let row_id = format!("item_evidence:{item_id}:{evidence_id}");
            insert_preview_row(transaction, token, "evidence_records", &row_id, &row_id)?;
        }
    }
    let mut decision_ids = BTreeSet::new();
    for entity_id in item_ids.iter().chain(evidence_ids.iter()) {
        let mut statement = transaction
            .prepare("SELECT decision_id FROM decision_entities WHERE entity_id = ?1")?;
        decision_ids.extend(
            statement
                .query_map([entity_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    for decision_id in decision_ids {
        insert_preview_row(
            transaction,
            token,
            "decision_records",
            &decision_id,
            &decision_id,
        )?;
        insert_related_rows(
            transaction,
            token,
            "decision_records",
            "decision_entities",
            "entity_id",
            "decision_id",
            &decision_id,
        )?;
    }
    for item_id in &item_ids {
        insert_related_rows(
            transaction,
            token,
            "remote_references",
            "remote_references",
            "remote_reference_id",
            "item_id",
            item_id,
        )?;
    }

    for id in receipt.evidence_rows() {
        insert_preview_row(transaction, token, "evidence_records", &id, &id)?;
    }
    for id in receipt.decision_rows() {
        insert_preview_row(transaction, token, "decision_records", &id, &id)?;
    }

    let try_on_approvals = try_on_deletion_approvals(transaction, &source_ids, &item_ids)?;
    materialize_blob_rows(
        transaction,
        token,
        &source_ids,
        &receipt.command_request_ids,
        &try_on_approvals,
    )?;
    augment_receipt_image_deletion_closure(transaction, token, &source_ids)?;
    augment_photo_deletion_closure(transaction, token, &source_ids, &try_on_approvals)?;
    augment_reconciliation_deletion_closure(transaction, token, &source_ids, &item_ids)?;
    materialize_affected_outfits(transaction, token, &item_ids)?;
    augment_recommendation_deletion_closure(transaction, token, &item_ids)?;
    augment_try_on_deletion_closure(transaction, token, &try_on_approvals)?;
    classify_prior_preview_rows(transaction, token, kind, target_id, &source_ids, &item_ids)?;
    Ok(())
}

fn materialize_affected_outfits(
    connection: &Connection,
    token: &str,
    item_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut outfit_ids = BTreeSet::new();
    for item_id in item_ids {
        extend_query(
            connection,
            "SELECT outfit_id FROM outfit_members WHERE item_id=?1",
            item_id,
            &mut outfit_ids,
        )?;
    }
    for outfit_id in outfit_ids {
        insert_preview_row(
            connection,
            token,
            "decision_records",
            &format!("outfit:{outfit_id}"),
            &format!("outfit:{outfit_id}"),
        )?;
        let request_id: String = connection.query_row(
            "SELECT request_id FROM outfits WHERE outfit_id=?1",
            [&outfit_id],
            |row| row.get(0),
        )?;
        insert_preview_row(
            connection,
            token,
            "decision_records",
            &format!("outfit_command_receipt:{request_id}"),
            &format!("outfit_command_receipt:{request_id}"),
        )?;
        let mut members =
            connection.prepare("SELECT ordinal FROM outfit_members WHERE outfit_id=?1")?;
        for ordinal in members
            .query_map([&outfit_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            let row = format!("outfit_member:{outfit_id}:{ordinal}");
            insert_preview_row(connection, token, "decision_records", &row, &row)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct ReceiptDeletionClosure {
    parse_ids: BTreeSet<String>,
    fragment_ids: BTreeSet<String>,
    run_ids: BTreeSet<String>,
    order_ids: BTreeSet<String>,
    line_ids: BTreeSet<String>,
    variant_ids: BTreeSet<String>,
    field_ids: BTreeSet<String>,
    citation_ids: BTreeSet<String>,
    review_decision_ids: BTreeSet<String>,
    review_head_order_ids: BTreeSet<String>,
    command_request_ids: BTreeSet<String>,
    command_entity_ids: BTreeSet<String>,
}

impl ReceiptDeletionClosure {
    fn evidence_rows(&self) -> Vec<String> {
        [
            ("receipt_parse", &self.parse_ids),
            ("receipt_fragment", &self.fragment_ids),
            ("receipt_run", &self.run_ids),
            ("receipt_order", &self.order_ids),
            ("receipt_line", &self.line_ids),
            ("receipt_variant", &self.variant_ids),
            ("receipt_field", &self.field_ids),
            ("receipt_citation", &self.citation_ids),
        ]
        .into_iter()
        .flat_map(|(kind, ids)| ids.iter().map(move |id| format!("{kind}:{id}")))
        .collect()
    }

    fn decision_rows(&self) -> Vec<String> {
        let mut rows = self
            .review_decision_ids
            .iter()
            .map(|id| format!("receipt_review_decision:{id}"))
            .collect::<Vec<_>>();
        rows.extend(
            self.review_head_order_ids
                .iter()
                .map(|id| format!("receipt_review_head:{id}")),
        );
        rows.extend(self.command_entity_ids.iter().cloned());
        rows.extend(
            self.command_request_ids
                .iter()
                .map(|id| format!("receipt_command_receipt:{id}")),
        );
        rows
    }
}

fn expand_deletion_closure(
    connection: &Connection,
    source_ids: &mut BTreeSet<String>,
    evidence_ids: &mut BTreeSet<String>,
    item_ids: &mut BTreeSet<String>,
) -> PlatformResult<ReceiptDeletionClosure> {
    let mut receipt = ReceiptDeletionClosure::default();
    loop {
        let before = (
            source_ids.len(),
            evidence_ids.len(),
            item_ids.len(),
            receipt.parse_ids.len(),
            receipt.run_ids.len(),
            receipt.order_ids.len(),
            receipt.line_ids.len(),
            receipt.review_decision_ids.len(),
            receipt.command_request_ids.len(),
        );

        for source_id in source_ids.clone() {
            collect_source_descendants(connection, &source_id, source_ids)?;
            extend_query(
                connection,
                "SELECT evidence_id FROM evidence WHERE source_id = ?1",
                &source_id,
                evidence_ids,
            )?;
            extend_query(
                connection,
                "SELECT parse_id FROM receipt_parses WHERE source_id = ?1",
                &source_id,
                &mut receipt.parse_ids,
            )?;
        }
        for item_id in item_ids.clone() {
            evidence_ids.extend(item_evidence_ids(connection, &item_id)?);
        }
        for evidence_id in evidence_ids.clone() {
            extend_query(
                connection,
                "SELECT source_id FROM evidence WHERE evidence_id = ?1",
                &evidence_id,
                source_ids,
            )?;
            extend_query(
                connection,
                "SELECT item_id FROM item_evidence WHERE evidence_id = ?1",
                &evidence_id,
                item_ids,
            )?;
            extend_query(
                connection,
                "SELECT order_line_id FROM receipt_order_lines WHERE evidence_id = ?1",
                &evidence_id,
                &mut receipt.line_ids,
            )?;
        }
        for parse_id in receipt.parse_ids.clone() {
            extend_query(
                connection,
                "SELECT source_id FROM receipt_parses WHERE parse_id = ?1",
                &parse_id,
                source_ids,
            )?;
            extend_query(
                connection,
                "SELECT run_id FROM receipt_extraction_runs WHERE parse_id = ?1",
                &parse_id,
                &mut receipt.run_ids,
            )?;
        }
        for run_id in receipt.run_ids.clone() {
            extend_query(
                connection,
                "SELECT parse_id FROM receipt_extraction_runs WHERE run_id = ?1",
                &run_id,
                &mut receipt.parse_ids,
            )?;
            extend_query(
                connection,
                "SELECT order_evidence_id FROM receipt_orders WHERE run_id = ?1",
                &run_id,
                &mut receipt.order_ids,
            )?;
        }
        for order_id in receipt.order_ids.clone() {
            extend_query(
                connection,
                "SELECT run_id FROM receipt_orders WHERE order_evidence_id = ?1",
                &order_id,
                &mut receipt.run_ids,
            )?;
            extend_query(
                connection,
                "SELECT order_line_id FROM receipt_order_lines WHERE order_evidence_id = ?1",
                &order_id,
                &mut receipt.line_ids,
            )?;
            extend_query(
                connection,
                "SELECT review_decision_id FROM receipt_review_decisions
                 WHERE order_evidence_id = ?1",
                &order_id,
                &mut receipt.review_decision_ids,
            )?;
            if connection
                .query_row(
                    "SELECT 1 FROM receipt_review_heads WHERE order_evidence_id = ?1",
                    [&order_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                receipt.review_head_order_ids.insert(order_id);
            }
        }
        for line_id in receipt.line_ids.clone() {
            extend_query(
                connection,
                "SELECT order_evidence_id FROM receipt_order_lines WHERE order_line_id = ?1",
                &line_id,
                &mut receipt.order_ids,
            )?;
            extend_query(
                connection,
                "SELECT evidence_id FROM receipt_order_lines
                 WHERE order_line_id = ?1 AND evidence_id IS NOT NULL",
                &line_id,
                evidence_ids,
            )?;
            extend_query(
                connection,
                "SELECT variant_evidence_id FROM receipt_variant_evidence
                 WHERE order_line_id = ?1",
                &line_id,
                &mut receipt.variant_ids,
            )?;
        }
        for decision_id in receipt.review_decision_ids.clone() {
            extend_query(
                connection,
                "SELECT order_evidence_id FROM receipt_review_decisions
                 WHERE review_decision_id = ?1",
                &decision_id,
                &mut receipt.order_ids,
            )?;
        }

        let mut command_request_ids = receipt.command_request_ids.clone();
        collect_receipt_command_requests(
            connection,
            source_ids,
            &receipt,
            &mut command_request_ids,
        )?;
        receipt.command_request_ids = command_request_ids;
        for request_id in receipt.command_request_ids.clone() {
            let mut statement = connection.prepare(
                "SELECT entity_kind, entity_id FROM receipt_command_entities
                 WHERE request_id = ?1",
            )?;
            for row in statement
                .query_map([&request_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
            {
                let (entity_kind, entity_id) = row;
                receipt.command_entity_ids.insert(format!(
                    "receipt_command_entity:{request_id}:{entity_kind}:{entity_id}"
                ));
                match entity_kind.as_str() {
                    "source" => {
                        source_ids.insert(entity_id);
                    }
                    "parse" => {
                        receipt.parse_ids.insert(entity_id);
                    }
                    "order" => {
                        receipt.order_ids.insert(entity_id);
                    }
                    "review_decision" => {
                        receipt.review_decision_ids.insert(entity_id);
                    }
                    _ => return Err(PlatformError::Corrupt("receipt_command_entity_kind")),
                }
            }
        }

        let after = (
            source_ids.len(),
            evidence_ids.len(),
            item_ids.len(),
            receipt.parse_ids.len(),
            receipt.run_ids.len(),
            receipt.order_ids.len(),
            receipt.line_ids.len(),
            receipt.review_decision_ids.len(),
            receipt.command_request_ids.len(),
        );
        if before == after {
            break;
        }
    }

    for parse_id in receipt.parse_ids.clone() {
        extend_query(
            connection,
            "SELECT fragment_id FROM receipt_fragments WHERE parse_id = ?1",
            &parse_id,
            &mut receipt.fragment_ids,
        )?;
    }
    for order_id in receipt.order_ids.clone() {
        extend_query(
            connection,
            "SELECT field_id FROM receipt_fields WHERE order_evidence_id = ?1",
            &order_id,
            &mut receipt.field_ids,
        )?;
    }
    for line_id in receipt.line_ids.clone() {
        extend_query(
            connection,
            "SELECT field_id FROM receipt_fields WHERE order_line_id = ?1",
            &line_id,
            &mut receipt.field_ids,
        )?;
    }
    for variant_id in receipt.variant_ids.clone() {
        extend_query(
            connection,
            "SELECT field_id FROM receipt_fields WHERE variant_evidence_id = ?1",
            &variant_id,
            &mut receipt.field_ids,
        )?;
    }
    for field_id in receipt.field_ids.clone() {
        extend_query(
            connection,
            "SELECT citation_id FROM receipt_field_citations WHERE field_id = ?1",
            &field_id,
            &mut receipt.citation_ids,
        )?;
    }
    Ok(receipt)
}

fn collect_receipt_command_requests(
    connection: &Connection,
    source_ids: &BTreeSet<String>,
    receipt: &ReceiptDeletionClosure,
    output: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    for (kind, ids) in [
        ("source", source_ids),
        ("parse", &receipt.parse_ids),
        ("order", &receipt.order_ids),
        ("review_decision", &receipt.review_decision_ids),
    ] {
        for id in ids {
            let mut statement = connection.prepare(
                "SELECT request_id FROM receipt_command_entities
                 WHERE entity_kind = ?1 AND entity_id = ?2",
            )?;
            output.extend(
                statement
                    .query_map(params![kind, id], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    Ok(())
}

fn extend_query(
    connection: &Connection,
    sql: &str,
    value: &str,
    output: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    let mut statement = connection.prepare(sql)?;
    output.extend(
        statement
            .query_map([value], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?,
    );
    Ok(())
}

fn insert_related_rows(
    connection: &Connection,
    token: &str,
    class: &str,
    table: &str,
    id_column: &str,
    foreign_column: &str,
    foreign_id: &str,
) -> PlatformResult<()> {
    let allowed = [
        ("source_provenance", "provenance_id", "source_id"),
        ("import_scans", "scan_id", "root_id"),
        ("quarantine_records", "quarantine_id", "source_id"),
        ("mime_parts", "part_id", "source_id"),
        ("derivatives", "derivative_id", "source_id"),
        ("remote_references", "remote_reference_id", "source_id"),
        ("remote_references", "remote_reference_id", "item_id"),
        ("decision_entities", "entity_id", "decision_id"),
    ];
    if !allowed.contains(&(table, id_column, foreign_column)) {
        return Err(PlatformError::Corrupt("deletion_classification_query"));
    }
    let sql = format!("SELECT {id_column} FROM {table} WHERE {foreign_column} = ?1");
    let mut statement = connection.prepare(&sql)?;
    for id in statement
        .query_map([foreign_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
    {
        let row_id = if table == "decision_entities" {
            format!("decision_entity:{foreign_id}:{id}")
        } else {
            format!("{table}:{id}")
        };
        insert_preview_row(connection, token, class, &row_id, &row_id)?;
    }
    Ok(())
}

fn try_on_deletion_approvals(
    connection: &Connection,
    source_ids: &BTreeSet<String>,
    item_ids: &BTreeSet<String>,
) -> PlatformResult<BTreeSet<String>> {
    let mut approvals = BTreeSet::new();
    for source_id in source_ids {
        extend_query(
            connection,
            "SELECT DISTINCT approval_id FROM try_on_assets WHERE source_id = ?1",
            source_id,
            &mut approvals,
        )?;
        extend_query(
            connection,
            "SELECT DISTINCT asset.approval_id
             FROM try_on_assets asset
             JOIN photo_source_revisions revision
               ON revision.source_revision_id = asset.source_revision_id
             WHERE revision.source_id = ?1",
            source_id,
            &mut approvals,
        )?;
    }
    for item_id in item_ids {
        extend_query(
            connection,
            "SELECT DISTINCT approval_id FROM try_on_assets WHERE item_id = ?1",
            item_id,
            &mut approvals,
        )?;
    }
    Ok(approvals)
}

fn augment_try_on_deletion_closure(
    connection: &Connection,
    token: &str,
    approval_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    for approval_id in approval_ids {
        insert_preview_row(
            connection,
            token,
            "source_records",
            &format!("try_on_approval:{approval_id}"),
            &format!("try_on_approval:{approval_id}"),
        )?;
        let (preview_request_id, retention_mode): (String, String) = connection.query_row(
            "SELECT preview_request_id, retention_mode
             FROM try_on_approvals WHERE approval_id = ?1",
            [approval_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        insert_preview_row(
            connection,
            token,
            "decision_records",
            &format!("try_on_command_receipt:{preview_request_id}"),
            &format!("try_on_command_receipt:{preview_request_id}"),
        )?;

        let mut assets = connection.prepare(
            "SELECT asset_ordinal FROM try_on_assets
             WHERE approval_id = ?1 ORDER BY asset_ordinal",
        )?;
        for ordinal in assets
            .query_map([approval_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            let id = format!("try_on_asset:{approval_id}:{ordinal}");
            insert_preview_row(connection, token, "evidence_records", &id, &id)?;
        }

        let mut jobs = connection
            .prepare("SELECT job_id, request_id FROM try_on_jobs WHERE approval_id = ?1")?;
        for (job_id, request_id) in jobs
            .query_map([approval_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            let job_row = format!("try_on_job:{job_id}");
            insert_preview_row(connection, token, "decision_records", &job_row, &job_row)?;
            let receipt = format!("try_on_command_receipt:{request_id}");
            insert_preview_row(connection, token, "decision_records", &receipt, &receipt)?;
            let mut attempts = connection.prepare(
                "SELECT attempt_id, state, audit_json,
                        CAST(json_extract(audit_json, '$.transport_started_at_ms') AS INTEGER)
                 FROM try_on_attempts WHERE job_id = ?1",
            )?;
            let mut transport_started_at_ms = None;
            for (attempt_id, state, audit_json, started_at_ms) in attempts
                .query_map([&job_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
            {
                if audit_json.is_some() {
                    transport_started_at_ms = started_at_ms;
                }
                let attempt = format!("try_on_attempt:{attempt_id}");
                insert_preview_row(connection, token, "decision_records", &attempt, &attempt)?;
                if state == "materializing" {
                    let intent = format!("try_on_materialization_intent:{attempt_id}");
                    insert_preview_row(connection, token, "decision_records", &intent, &intent)?;
                }
            }
            if let Some(started_at_ms) = transport_started_at_ms {
                let remote = format!("try_on_remote_reference:{job_id}");
                let label = try_on_remote_retention_label(&retention_mode, started_at_ms)?;
                insert_preview_row(connection, token, "remote_references", &remote, &label)?;
            }

            let output = connection
                .query_row(
                    "SELECT output_id FROM try_on_outputs WHERE job_id = ?1",
                    [&job_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(output_id) = output {
                let output_row = format!("try_on_output:{output_id}");
                insert_preview_row(connection, token, "derivatives", &output_row, &output_row)?;
                let provenance = format!("try_on_provenance:{output_id}");
                insert_preview_row(
                    connection,
                    token,
                    "evidence_records",
                    &provenance,
                    &provenance,
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct BlobClosure {
    candidate_kind: BTreeMap<String, &'static str>,
    closed_references: BTreeMap<String, BTreeMap<&'static str, i64>>,
}

fn materialize_blob_rows(
    connection: &Connection,
    token: &str,
    source_ids: &BTreeSet<String>,
    command_request_ids: &BTreeSet<String>,
    try_on_approval_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut closure = BlobClosure::default();
    for source_id in source_ids {
        collect_blob_reference(
            connection,
            "SELECT blob_sha256 FROM local_sources
             WHERE source_id = ?1 AND blob_sha256 IS NOT NULL",
            source_id,
            "originals",
            "local_source",
            &mut closure,
        )?;
        collect_blob_reference(
            connection,
            "SELECT blob_sha256 FROM source_provenance
             WHERE source_id = ?1 AND blob_sha256 IS NOT NULL",
            source_id,
            "originals",
            "source_provenance",
            &mut closure,
        )?;
        collect_blob_reference(
            connection,
            "SELECT materialization.blob_sha256
             FROM gmail_revision_materializations materialization
             WHERE materialization.local_source_id = ?1
               AND materialization.blob_sha256 IS NOT NULL",
            source_id,
            "originals",
            "gmail_materialization",
            &mut closure,
        )?;
        collect_blob_reference(
            connection,
            "SELECT blob_sha256 FROM derivatives WHERE source_id = ?1",
            source_id,
            "derivatives",
            "derivative",
            &mut closure,
        )?;
    }
    for request_id in command_request_ids {
        collect_blob_reference(
            connection,
            "SELECT blob_sha256 FROM storage_checks WHERE request_id = ?1",
            request_id,
            "originals",
            "storage_check",
            &mut closure,
        )?;
    }
    for approval_id in try_on_approval_ids {
        collect_blob_reference(
            connection,
            "SELECT parent_blob_sha256 FROM try_on_assets WHERE approval_id = ?1",
            approval_id,
            "originals",
            "try_on_asset",
            &mut closure,
        )?;
        collect_blob_reference(
            connection,
            "SELECT output.blob_sha256
             FROM try_on_outputs output
             JOIN try_on_jobs job ON job.job_id = output.job_id
             WHERE job.approval_id = ?1",
            approval_id,
            "derivatives",
            "try_on_output",
            &mut closure,
        )?;
    }

    for (blob, owned_class) in closure.candidate_kind {
        let owners = blob_reference_owners(connection, &blob)?;
        let closed = closure.closed_references.get(&blob);
        let surviving_owners = owners
            .into_iter()
            .filter_map(|(owner, count)| {
                let closed_count = closed
                    .and_then(|owners| owners.get(owner))
                    .copied()
                    .unwrap_or(0);
                let surviving = count.saturating_sub(closed_count);
                (surviving > 0).then_some((owner, surviving))
            })
            .collect::<BTreeMap<_, _>>();
        let surviving: i64 = surviving_owners.values().sum();
        if surviving > 0 {
            let owner_names = surviving_owners.into_keys().collect::<Vec<_>>().join(",");
            let label = format!("{blob} refs={surviving} owners={owner_names}");
            insert_preview_row(connection, token, "retained_shared_blobs", &blob, &label)?;
        } else {
            insert_preview_row(connection, token, owned_class, &blob, &blob)?;
        }
    }
    Ok(())
}

fn collect_blob_reference(
    connection: &Connection,
    sql: &str,
    value: &str,
    class: &'static str,
    owner: &'static str,
    closure: &mut BlobClosure,
) -> PlatformResult<()> {
    let mut statement = connection.prepare(sql)?;
    for blob in statement
        .query_map([value], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
    {
        closure
            .candidate_kind
            .entry(blob.clone())
            .and_modify(|existing| {
                if class == "originals" {
                    *existing = class;
                }
            })
            .or_insert(class);
        *closure
            .closed_references
            .entry(blob)
            .or_default()
            .entry(owner)
            .or_default() += 1;
    }
    Ok(())
}

fn blob_reference_owners(
    connection: &Connection,
    blob: &str,
) -> PlatformResult<BTreeMap<&'static str, i64>> {
    let queries = [
        (
            "local_source",
            "SELECT COUNT(*) FROM local_sources WHERE blob_sha256 = ?1",
        ),
        (
            "source_provenance",
            "SELECT COUNT(*) FROM source_provenance WHERE blob_sha256 = ?1",
        ),
        (
            "provenance",
            "SELECT COUNT(*) FROM provenance WHERE blob_sha256 = ?1",
        ),
        (
            "storage_check",
            "SELECT COUNT(*) FROM storage_checks WHERE blob_sha256 = ?1",
        ),
        (
            "derivative",
            "SELECT COUNT(*) FROM derivatives WHERE blob_sha256 = ?1",
        ),
        (
            "receipt_remote_image_source",
            "SELECT COUNT(*) FROM receipt_remote_images WHERE source_blob_sha256 = ?1",
        ),
        (
            "receipt_remote_image_display",
            "SELECT COUNT(*) FROM receipt_remote_images WHERE display_blob_sha256 = ?1",
        ),
        (
            "receipt_image_intent_source",
            "SELECT COUNT(*) FROM receipt_image_materialization_intents
             WHERE source_blob_sha256 = ?1",
        ),
        (
            "receipt_image_intent_display",
            "SELECT COUNT(*) FROM receipt_image_materialization_intents
             WHERE display_blob_sha256 = ?1",
        ),
        (
            "photo_source_revision",
            "SELECT COUNT(*) FROM photo_source_revisions WHERE blob_sha256 = ?1",
        ),
        (
            "photo_segmentation_attempt",
            "SELECT COUNT(*) FROM photo_segmentation_attempts WHERE input_blob_sha256 = ?1",
        ),
        (
            "photo_artifact",
            "SELECT COUNT(*) FROM photo_artifacts WHERE input_blob_sha256 = ?1",
        ),
        (
            "gmail_materialization",
            "SELECT COUNT(*) FROM gmail_revision_materializations
             WHERE blob_sha256 = ?1",
        ),
        (
            "outfit_member",
            "SELECT COUNT(*) FROM outfit_members WHERE blob_sha256 = ?1",
        ),
        (
            "try_on_asset",
            "SELECT COUNT(*) FROM try_on_assets WHERE parent_blob_sha256 = ?1",
        ),
        (
            "try_on_output",
            "SELECT COUNT(*) FROM try_on_outputs WHERE blob_sha256 = ?1",
        ),
    ];
    queries
        .into_iter()
        .map(|(kind, sql)| {
            let count = connection.query_row(sql, [blob], |row| row.get::<_, i64>(0))?;
            Ok((kind, count))
        })
        .collect()
}

pub(crate) fn complete_blob_owner_count(
    connection: &Connection,
    blob: &str,
) -> PlatformResult<i64> {
    blob_reference_owners(connection, blob)?
        .into_values()
        .try_fold(0_i64, |total, count| {
            total
                .checked_add(count)
                .ok_or(PlatformError::Corrupt("blob_owner_count"))
        })
}

fn try_on_remote_retention_label(mode: &str, dispatched_at_ms: i64) -> PlatformResult<String> {
    let qualifier = match mode {
        "unknown" | "default" => {
            let retention_until_ms = dispatched_at_ms
                .checked_add(30 * 24 * 60 * 60 * 1_000)
                .ok_or(PlatformError::Corrupt("try_on_retention_expiry"))?;
            let timestamp = OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(retention_until_ms) * 1_000_000,
            )
            .map_err(|_| PlatformError::Corrupt("try_on_retention_expiry"))?
            .format(&Rfc3339)
            .map_err(|_| PlatformError::Corrupt("try_on_retention_expiry"))?;
            format!(
                "default abuse-monitoring window through {timestamp}; flagged inputs may be retained for review"
            )
        }
        "MAM" => "declared modified abuse monitoring; expiry depends on project configuration"
            .to_owned(),
        "ZDR" => "declared ZDR; project enrollment not verified; flagged inputs may be retained for review"
            .to_owned(),
        _ => return Err(PlatformError::Corrupt("try_on_retention_mode")),
    };
    Ok(format!("OpenAI try-on remote reference ({qualifier})"))
}

fn expand_gmail_source_lineage(
    connection: &Connection,
    source_ids: &mut BTreeSet<String>,
) -> PlatformResult<BTreeSet<String>> {
    let mut provider_source_ids = BTreeSet::new();
    loop {
        let before = (source_ids.len(), provider_source_ids.len());
        for source_id in source_ids.clone() {
            extend_query(
                connection,
                "SELECT revision.provider_source_id
                 FROM gmail_revision_materializations materialization
                 JOIN gmail_source_revisions revision
                   ON revision.revision_id = materialization.revision_id
                 WHERE materialization.local_source_id = ?1",
                &source_id,
                &mut provider_source_ids,
            )?;
        }
        for provider_source_id in provider_source_ids.clone() {
            extend_query(
                connection,
                "SELECT materialization.local_source_id
                 FROM gmail_source_revisions revision
                 JOIN gmail_revision_materializations materialization
                   ON materialization.revision_id = revision.revision_id
                 WHERE revision.provider_source_id = ?1",
                &provider_source_id,
                source_ids,
            )?;
        }
        if before == (source_ids.len(), provider_source_ids.len()) {
            break;
        }
    }
    Ok(provider_source_ids)
}

fn materialize_gmail_lineage_rows(
    connection: &Connection,
    token: &str,
    provider_source_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    for provider_source_id in provider_source_ids {
        insert_preview_row(
            connection,
            token,
            "remote_references",
            &format!("gmail_provider_source:{provider_source_id}"),
            &format!(
                "gmail_provider_source:{provider_source_id}:mailbox_copy_retained_gmail_readonly"
            ),
        )?;
        let mut memberships = connection.prepare(
            "SELECT scope_id FROM gmail_scope_sources
             WHERE provider_source_id = ?1 ORDER BY scope_id",
        )?;
        for scope_id in memberships
            .query_map([provider_source_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            let id = format!("gmail_scope_source:{scope_id}:{provider_source_id}");
            insert_preview_row(connection, token, "remote_references", &id, &id)?;
        }
        if connection
            .query_row(
                "SELECT 1 FROM gmail_source_heads WHERE provider_source_id = ?1",
                [provider_source_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            let id = format!("gmail_source_head:{provider_source_id}");
            insert_preview_row(connection, token, "source_records", &id, &id)?;
        }
        let mut revisions = connection.prepare(
            "SELECT revision_id FROM gmail_source_revisions
             WHERE provider_source_id = ?1 ORDER BY history_id, revision_id",
        )?;
        for revision_id in revisions
            .query_map([provider_source_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            let revision_row = format!("gmail_revision:{revision_id}");
            insert_preview_row(
                connection,
                token,
                "source_records",
                &revision_row,
                &revision_row,
            )?;
            let materialization_row = format!("gmail_materialization:{revision_id}");
            insert_preview_row(
                connection,
                token,
                "source_records",
                &materialization_row,
                &materialization_row,
            )?;
            let mut operations = connection.prepare(
                "SELECT request_id FROM gmail_operation_revisions
                 WHERE revision_id = ?1 ORDER BY request_id",
            )?;
            for request_id in operations
                .query_map([&revision_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
            {
                let id = format!("gmail_operation_revision:{request_id}:{revision_id}");
                insert_preview_row(connection, token, "decision_records", &id, &id)?;
            }
        }
    }
    Ok(())
}

fn classify_prior_preview_rows(
    connection: &Connection,
    current_token: &str,
    target_kind: DeletionTargetKindV1,
    target_id: &str,
    source_ids: &BTreeSet<String>,
    item_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut statement = connection.prepare(
        "SELECT snapshot_token, target_kind, target_id FROM deletion_previews
         WHERE snapshot_token <> ?1",
    )?;
    for (prior, prior_kind, prior_target) in statement
        .query_map([current_token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    {
        let reachable = match prior_kind.as_str() {
            "source" => source_ids.contains(&prior_target),
            "item" => item_ids.contains(&prior_target),
            "import_root" => {
                target_kind == DeletionTargetKindV1::ImportRoot && prior_target == target_id
            }
            "photokit_enrollment" => {
                target_kind == DeletionTargetKindV1::PhotoKitEnrollment && prior_target == target_id
            }
            "photokit_asset" => {
                target_kind == DeletionTargetKindV1::PhotoKitAsset && prior_target == target_id
            }
            _ => return Err(PlatformError::Corrupt("deletion_preview_target_kind")),
        };
        if !reachable {
            continue;
        }
        let preview_id = format!("deletion_preview:{prior}");
        insert_preview_row(
            connection,
            current_token,
            "decision_records",
            &preview_id,
            &preview_id,
        )?;
        let mut rows = connection.prepare(
            "SELECT dependency_class, entity_id FROM deletion_preview_items
             WHERE snapshot_token = ?1",
        )?;
        for (class, entity_id) in rows
            .query_map([&prior], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            let row_id = format!("deletion_preview_item:{prior}:{class}:{entity_id}");
            insert_preview_row(
                connection,
                current_token,
                "decision_records",
                &row_id,
                &row_id,
            )?;
        }
    }
    Ok(())
}

fn augment_recommendation_deletion_closure(
    connection: &Connection,
    token: &str,
    item_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut attempt_ids = BTreeSet::new();
    for item_id in item_ids {
        let mut members = connection.prepare(
            "SELECT attempt_id, proposal_ordinal, member_ordinal
             FROM outfit_recommendation_members
             WHERE item_id = ?1
             ORDER BY attempt_id, proposal_ordinal, member_ordinal",
        )?;
        for (attempt_id, proposal_ordinal, member_ordinal) in members
            .query_map([item_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            attempt_ids.insert(attempt_id.clone());
            let id = format!(
                "outfit_recommendation_member:{attempt_id}:{proposal_ordinal}:{member_ordinal}"
            );
            insert_preview_row(connection, token, "decision_records", &id, &id)?;
        }
    }

    for attempt_id in attempt_ids {
        let attempt_row = format!("outfit_recommendation_attempt:{attempt_id}");
        insert_preview_row(
            connection,
            token,
            "decision_records",
            &attempt_row,
            &attempt_row,
        )?;
        let (approval_id, request_id): (String, String) = connection.query_row(
            "SELECT approval_id, request_id
             FROM outfit_recommendation_attempts WHERE attempt_id = ?1",
            [&attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let approval_row = format!("outfit_recommendation_approval:{approval_id}");
        insert_preview_row(
            connection,
            token,
            "decision_records",
            &approval_row,
            &approval_row,
        )?;
        let preview_request_id: String = connection.query_row(
            "SELECT preview_request_id
             FROM outfit_recommendation_approvals WHERE approval_id = ?1",
            [&approval_id],
            |row| row.get(0),
        )?;
        for receipt_id in [preview_request_id, request_id] {
            if connection
                .query_row(
                    "SELECT 1 FROM command_receipts WHERE request_id = ?1",
                    [&receipt_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                let id = format!("outfit_recommendation_command_receipt:{receipt_id}");
                insert_preview_row(connection, token, "decision_records", &id, &id)?;
            }
        }

        let mut proposals = connection.prepare(
            "SELECT ordinal FROM outfit_recommendation_proposals
             WHERE attempt_id = ?1 ORDER BY ordinal",
        )?;
        for ordinal in proposals
            .query_map([&attempt_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            let id = format!("outfit_recommendation_proposal:{attempt_id}:{ordinal}");
            insert_preview_row(connection, token, "decision_records", &id, &id)?;
        }
    }
    Ok(())
}

fn collect_source_descendants(
    connection: &Connection,
    source_id: &str,
    output: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    let mut queue = vec![source_id.to_owned()];
    while let Some(parent) = queue.pop() {
        let mut statement = connection
            .prepare("SELECT source_id FROM local_sources WHERE parent_source_id = ?1")?;
        for child in statement
            .query_map([parent], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            if output.insert(child.clone()) {
                queue.push(child);
            }
        }
    }
    Ok(())
}

fn insert_preview_row(
    connection: &Connection,
    token: &str,
    class: &str,
    entity_id: &str,
    label: &str,
) -> PlatformResult<()> {
    connection.execute(
        "INSERT OR IGNORE INTO deletion_preview_items(
            snapshot_token, dependency_class, entity_id, sort_key
         ) VALUES (?1, ?2, ?3, ?4)",
        params![token, class, entity_id, label],
    )?;
    Ok(())
}

fn deletion_counts(
    connection: &Connection,
    token: &str,
) -> PlatformResult<Vec<DeletionClassCountV1>> {
    deletion_classes()
        .into_iter()
        .map(|class| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM deletion_preview_items
                 WHERE snapshot_token = ?1 AND dependency_class = ?2",
                params![token, deletion_class_db(class)],
                |row| row.get(0),
            )?;
            Ok(DeletionClassCountV1 {
                class,
                count: count as u64,
            })
        })
        .collect()
}

fn deletion_page(
    connection: &Connection,
    token: &str,
    class: DeletionDependencyClassV1,
    offset: u64,
    limit: u16,
) -> PlatformResult<(Vec<DeletionPlanItemV1>, Option<PageCursorV1>, u64)> {
    let class_db = deletion_class_db(class);
    let total: i64 = connection.query_row(
        "SELECT COUNT(*) FROM deletion_preview_items
         WHERE snapshot_token = ?1 AND dependency_class = ?2",
        params![token, class_db],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT entity_id, sort_key FROM deletion_preview_items
         WHERE snapshot_token = ?1 AND dependency_class = ?2
         ORDER BY sort_key, entity_id LIMIT ?3 OFFSET ?4",
    )?;
    let items = statement
        .query_map(
            params![token, class_db, i64::from(limit), offset as i64],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(record_id, display_label)| DeletionPlanItemV1 {
            class,
            record_id,
            display_label,
            retained: class == DeletionDependencyClassV1::RetainedSharedBlobs,
        })
        .collect::<Vec<_>>();
    let next_offset = offset + items.len() as u64;
    let next_cursor = if next_offset < total as u64 {
        Some(
            PageCursorV1::new(format!(
                "delete.{token}.{}.{next_offset}",
                deletion_class_db(class)
            ))
            .map_err(|_| PlatformError::Corrupt("cursor"))?,
        )
    } else {
        None
    };
    Ok((items, next_cursor, total as u64))
}

fn parse_deletion_cursor(
    cursor: Option<&PageCursorV1>,
    token: &str,
    class: DeletionDependencyClassV1,
) -> PlatformResult<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let expected = format!("delete.{token}.{}.", deletion_class_db(class));
    cursor
        .as_str()
        .strip_prefix(&expected)
        .ok_or(PlatformError::Conflict("snapshot_expired"))?
        .parse()
        .map_err(|_| PlatformError::InvalidInput("cursor"))
}

fn make_snapshot_token(value: &str) -> PlatformResult<DeletionSnapshotTokenV1> {
    DeletionSnapshotTokenV1::new(value.to_owned())
        .map_err(|_| PlatformError::Corrupt("snapshot_token"))
}

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))
}

fn parse_item_id(value: &str) -> PlatformResult<ItemId> {
    ItemId::new(parse_uuid(value, "item_id")?).map_err(|_| PlatformError::Corrupt("item_id"))
}

fn parse_evidence_id(value: &str) -> PlatformResult<EvidenceId> {
    EvidenceId::new(parse_uuid(value, "evidence_id")?)
        .map_err(|_| PlatformError::Corrupt("evidence_id"))
}

fn parse_source_id(value: &str) -> PlatformResult<wardrobe_core::SourceId> {
    wardrobe_core::SourceId::new(parse_uuid(value, "source_id")?)
        .map_err(|_| PlatformError::Corrupt("source_id"))
}

fn parse_import_root_id(value: &str) -> PlatformResult<ImportRootId> {
    ImportRootId::new(parse_uuid(value, "import_root_id")?)
        .map_err(|_| PlatformError::Corrupt("import_root_id"))
}

fn parse_decision_id(value: &str) -> PlatformResult<DecisionId> {
    DecisionId::new(parse_uuid(value, "decision_id")?)
        .map_err(|_| PlatformError::Corrupt("decision_id"))
}

fn parse_quarantine_id(value: &str) -> PlatformResult<QuarantineId> {
    QuarantineId::new(parse_uuid(value, "quarantine_id")?)
        .map_err(|_| PlatformError::Corrupt("quarantine_id"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn port_error(error: PlatformError) -> CatalogPortError {
    let kind = match error {
        PlatformError::Conflict("snapshot_expired") => CatalogPortErrorKind::SnapshotExpired,
        PlatformError::Conflict(_) | PlatformError::LeaseLost => CatalogPortErrorKind::Conflict,
        PlatformError::InvalidInput("split_evidence_partition")
        | PlatformError::InvalidInput("evidence_id") => CatalogPortErrorKind::InvalidState,
        PlatformError::InvalidInput(_) => CatalogPortErrorKind::NotFound,
        PlatformError::Corrupt(_) => CatalogPortErrorKind::DataIntegrity,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            CatalogPortErrorKind::PermissionDenied
        }
        PlatformError::Io(_) | PlatformError::Sqlite(_) => CatalogPortErrorKind::Unavailable,
        _ => CatalogPortErrorKind::Internal,
    };
    CatalogPortError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateAppPaths;
    use image::{ColorType, ImageFormat};
    use std::fs;
    use std::os::unix::fs::symlink;
    use wardrobe_core::{ItemCategoryV1, SplitGroupV1};

    #[test]
    fn deletion_schema_classification_covers_every_phase_table_and_blob_fk() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let connection = database.connection().unwrap();

        let classified_receipt_tables = [
            "receipt_parses",
            "receipt_fragments",
            "receipt_extraction_runs",
            "receipt_orders",
            "receipt_order_lines",
            "receipt_variant_evidence",
            "receipt_fields",
            "receipt_field_citations",
            "receipt_review_decisions",
            "receipt_review_heads",
            "receipt_command_entities",
            "receipt_image_candidates",
            "receipt_image_candidate_overflow",
            "receipt_image_approvals",
            "receipt_image_attempts",
            "receipt_image_attempt_outcomes",
            "receipt_image_hops",
            "receipt_image_materialization_intents",
            "receipt_remote_images",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let mut statement = connection
            .prepare(
                "SELECT name FROM pragma_table_list
                 WHERE type = 'table' AND name LIKE 'receipt_%' ORDER BY name",
            )
            .unwrap();
        let actual_receipt_tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert_eq!(actual_receipt_tables, classified_receipt_tables);

        let classified_photo_tables = [
            "photo_scopes",
            "photo_source_revisions",
            "photo_scope_members",
            "photo_analysis_runs",
            "photo_analysis_member_claims",
            "photo_segmentation_attempts",
            "photo_segmentation_outcomes",
            "photo_artifacts",
            "photo_artifact_parents",
            "photo_observations",
            "photo_review_decisions",
            "photo_review_heads",
            "photo_command_entities",
            "photo_person_detection_runs",
            "photo_person_detection_attempts",
            "photo_person_instances",
            "photo_owner_preview_references",
            "photo_owner_reviews",
            "photo_detection_corrections",
            "photo_owner_decisions",
            "photo_owner_heads",
            "photo_owner_work_claims",
            "photo_observation_owner_links",
            "photo_owner_command_entities",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let mut statement = connection
            .prepare(
                "SELECT name FROM pragma_table_list
                 WHERE type = 'table' AND name GLOB 'photo_*' ORDER BY name",
            )
            .unwrap();
        let actual_photo_tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert_eq!(actual_photo_tables, classified_photo_tables);

        let classified_reconciliation_tables = [
            "reconciliation_cases",
            "reconciliation_candidates",
            "reconciliation_candidate_evidence",
            "reconciliation_evidence_input_hashes",
            "reconciliation_decisions",
            "reconciliation_decision_heads",
            "reconciliation_command_entities",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let mut statement = connection
            .prepare(
                "SELECT name FROM pragma_table_list
                 WHERE type = 'table' AND name LIKE 'reconciliation_%'
                 ORDER BY name",
            )
            .unwrap();
        let actual_reconciliation_tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert_eq!(
            actual_reconciliation_tables,
            classified_reconciliation_tables
        );

        let classified_recommendation_tables = [
            "outfit_recommendation_approvals",
            "outfit_recommendation_attempts",
            "outfit_recommendation_members",
            "outfit_recommendation_proposals",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let mut statement = connection
            .prepare(
                "SELECT name FROM pragma_table_list
                 WHERE type = 'table' AND name LIKE 'outfit_recommendation_%'
                 ORDER BY name",
            )
            .unwrap();
        let actual_recommendation_tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert_eq!(
            actual_recommendation_tables,
            classified_recommendation_tables
        );

        let classified_blob_tables = [
            "local_sources",
            "source_provenance",
            "provenance",
            "storage_checks",
            "derivatives",
            "receipt_remote_images",
            "photo_source_revisions",
            "photo_segmentation_attempts",
            "photo_artifacts",
            "photo_person_detection_attempts",
            "photo_owner_preview_references",
            "photokit_materializations",
            "gmail_revision_materializations",
            "outfit_members",
            "try_on_assets",
            "try_on_outputs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let mut tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let tables = tables
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut actual_blob_tables = BTreeSet::new();
        for table in tables {
            let sql = format!("SELECT \"table\" FROM pragma_foreign_key_list('{table}')");
            let mut foreign_keys = connection.prepare(&sql).unwrap();
            if foreign_keys
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .iter()
                .any(|target| target == "blobs")
            {
                actual_blob_tables.insert(table);
            }
        }
        assert_eq!(actual_blob_tables, classified_blob_tables);
    }

    fn request_id() -> wardrobe_core::RequestId {
        wardrobe_core::RequestId::new_v4()
    }

    fn attributes(name: &str) -> ItemAttributesV1 {
        ItemAttributesV1 {
            display_name: name.to_owned(),
            category: ItemCategoryV1::Top,
            subcategory: Some("T-Shirt".to_owned()),
            brand: None,
            primary_color: Some("White".to_owned()),
            size: None,
            notes: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn production_import_catalog_restart_undo_and_deletion_smoke() {
        let temporary = tempfile::tempdir().unwrap();
        let app_paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let imports = temporary.path().join("imports");
        let photos = imports.join("photos");
        fs::create_dir_all(&photos).unwrap();
        let pixels = [
            255_u8, 255, 255, 240, 240, 240, 230, 230, 230, 220, 220, 220,
        ];
        image::save_buffer_with_format(
            photos.join("shirt.png"),
            &pixels,
            2,
            2,
            ColorType::Rgb8,
            ImageFormat::Png,
        )
        .unwrap();
        fs::copy(photos.join("shirt.png"), photos.join("shirt-copy.png")).unwrap();
        fs::write(photos.join("spoofed.jpg"), b"not an image").unwrap();

        let eml = imports.join("order.eml");
        fs::write(
            &eml,
            b"From: shop@example.com\r\nSubject: order\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nOrder\r\n--x\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=shirt.png\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--x--\r\n",
        )
        .unwrap();
        symlink(&eml, photos.join("linked.jpg")).unwrap();
        let mbox = imports.join("orders.mbox");
        fs::write(
            &mbox,
            b"From shop Tue Jul 14 00:00:00 2026\nFrom: shop@example.com\nSubject: one\nContent-Type: text/plain\n\nfirst\nFrom shop Wed Jul 15 00:00:00 2026\nFrom: shop@example.com\nSubject: two\nContent-Type: text/plain\n\nsecond\n",
        )
        .unwrap();

        let database = Database::open(&app_paths, 1).unwrap();
        let import_request = ImportLocalSourcesV1Request {
            schema_version: 1,
            request_id: request_id(),
            paths: vec![
                photos.to_string_lossy().into_owned(),
                eml.to_string_lossy().into_owned(),
                mbox.to_string_lossy().into_owned(),
            ],
        };
        let imported = database.import_local_sources(&import_request).unwrap();
        assert!(
            imported
                .summaries
                .iter()
                .map(|value| value.imported)
                .sum::<u32>()
                >= 4
        );
        assert!(
            imported
                .summaries
                .iter()
                .map(|value| value.quarantined)
                .sum::<u32>()
                >= 1
        );
        let root_id = imported.summaries[0].import_root_id.unwrap();
        let changed_envelope = ImportLocalSourcesV1Request {
            schema_version: 1,
            request_id: import_request.request_id,
            paths: vec![eml.to_string_lossy().into_owned()],
        };
        assert_eq!(
            database
                .import_local_sources(&changed_envelope)
                .unwrap_err()
                .kind,
            CatalogPortErrorKind::Conflict
        );

        let moved_photos = imports.join("photos-away");
        fs::rename(&photos, &moved_photos).unwrap();
        let unavailable = database
            .refresh_import_roots(&RefreshImportRootsV1Request {
                schema_version: 1,
                request_id: request_id(),
                import_root_ids: vec![root_id],
            })
            .unwrap();
        assert_eq!(unavailable.summaries[0].unavailable, 1);
        let still_present: i64 = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM local_sources
                 WHERE root_id = ?1 AND status <> 'missing'",
                [root_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(still_present, 4);
        fs::rename(&moved_photos, &photos).unwrap();
        database
            .refresh_import_roots(&RefreshImportRootsV1Request {
                schema_version: 1,
                request_id: request_id(),
                import_root_ids: vec![root_id],
            })
            .unwrap();

        let connection = database.connection().unwrap();
        let distinct_sources: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM local_sources WHERE canonical_locator LIKE '%shirt%.png'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let distinct_blobs: i64 = connection
            .query_row(
                "SELECT COUNT(DISTINCT blob_sha256) FROM local_sources
                 WHERE canonical_locator LIKE '%shirt%.png'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(distinct_sources, 2);
        assert_eq!(distinct_blobs, 1);
        let quarantined_raw: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM local_sources
                 WHERE status = 'quarantined' AND blob_sha256 IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(quarantined_raw >= 1);
        drop(connection);

        let inbox = database
            .list_inbox(&ListInboxV1Request {
                schema_version: 1,
                request_id: request_id(),
                state: InboxStateV1::Unresolved,
                cursor: None,
                limit: 100,
            })
            .unwrap();
        assert!(inbox.evidence.len() >= 2);
        let first_evidence = inbox.evidence[0].evidence_id;
        let second_evidence = inbox.evidence[1].evidence_id;

        let first = database
            .save_item_and_append_decision(&SaveItemV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_id: None,
                attributes: attributes("White shirt"),
                evidence_ids: vec![first_evidence],
                expected_catalog_revision: 0,
            })
            .unwrap();
        let stale = database
            .save_item_and_append_decision(&SaveItemV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_id: None,
                attributes: attributes("Stale item"),
                evidence_ids: Vec::new(),
                expected_catalog_revision: 0,
            })
            .unwrap_err();
        assert_eq!(stale.kind, CatalogPortErrorKind::Conflict);
        let second = database
            .save_item_and_append_decision(&SaveItemV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_id: None,
                attributes: attributes("Order shirt"),
                evidence_ids: vec![second_evidence],
                expected_catalog_revision: 1,
            })
            .unwrap();
        let catalog_page = database
            .list_catalog(&ListCatalogV1Request {
                schema_version: 1,
                request_id: request_id(),
                cursor: None,
                limit: 1,
            })
            .unwrap();
        let stale_cursor = catalog_page.next_cursor.unwrap();
        let edited = database
            .save_item_and_append_decision(&SaveItemV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_id: Some(first.item.item_id),
                attributes: attributes("White date shirt"),
                evidence_ids: vec![first_evidence],
                expected_catalog_revision: 2,
            })
            .unwrap();
        assert_eq!(edited.item.attributes.display_name, "White date shirt");
        let expired = database
            .list_catalog(&ListCatalogV1Request {
                schema_version: 1,
                request_id: request_id(),
                cursor: Some(stale_cursor),
                limit: 1,
            })
            .unwrap_err();
        assert_eq!(expired.kind, CatalogPortErrorKind::SnapshotExpired);

        let merged = database
            .merge_items_and_append_decision(&MergeItemsV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_ids: vec![first.item.item_id, second.item.item_id],
                target_attributes: attributes("Merged shirt"),
                expected_catalog_revision: 3,
            })
            .unwrap();
        assert_eq!(merged.item.evidence_ids.len(), 2);
        let split = database
            .split_item_and_append_decision(&SplitItemV1Request {
                schema_version: 1,
                request_id: request_id(),
                item_id: merged.item.item_id,
                groups: vec![
                    SplitGroupV1 {
                        attributes: attributes("Shirt A"),
                        evidence_ids: vec![merged.item.evidence_ids[0]],
                    },
                    SplitGroupV1 {
                        attributes: attributes("Shirt B"),
                        evidence_ids: vec![merged.item.evidence_ids[1]],
                    },
                ],
                expected_catalog_revision: 4,
            })
            .unwrap();
        assert_eq!(split.items.len(), 2);
        let split_decision = split.decision.decision_id;
        drop(database);

        let restarted = Database::open(&app_paths, 2).unwrap();
        let undone = restarted
            .append_compensating_undo(&UndoDecisionV1Request {
                schema_version: 1,
                request_id: request_id(),
                decision_id: split_decision,
                expected_catalog_revision: 5,
            })
            .unwrap();
        assert_eq!(undone.restored_items.len(), 1);
        assert_eq!(undone.restored_items[0].evidence_ids.len(), 2);
        let preview = restarted
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: 1,
                request_id: request_id(),
                target_kind: DeletionTargetKindV1::Item,
                target_id: undone.restored_items[0].item_id.to_string(),
                limit: 1,
            })
            .unwrap();
        assert!(preview.overall_count > 0);
        let decision_page = restarted
            .list_deletion_plan_items(&ListDeletionPlanItemsV1Request {
                schema_version: 1,
                request_id: request_id(),
                preview_snapshot_token: preview.preview_snapshot_token,
                class: DeletionDependencyClassV1::DecisionRecords,
                cursor: None,
                limit: 1,
            })
            .unwrap();
        assert!(decision_page.total_count >= 1);
        let before: i64 = restarted
            .connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM local_sources", [], |row| row.get(0))
            .unwrap();
        assert!(before >= 6);
    }
}

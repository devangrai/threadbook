use crate::database::stable_id;
use crate::receipt_repository::{load_order, receipt_port_error};
use crate::{Database, PlatformError, PlatformResult};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use wardrobe_core::{
    CatalogItemV1, CorrectedReceiptOrderV1, DecisionId, DecisionKindV1, DecisionSnapshotV1,
    EvidenceId, ItemId, ListReceiptPurchaseUnitsV1Request, ListReceiptPurchaseUnitsV1Response,
    PageCursorV1, PromoteReceiptPurchaseUnitV1Request, PromoteReceiptPurchaseUnitV1Response,
    ReceiptAuthoritySnapshotId, ReceiptAuthoritySnapshotV1, ReceiptEventKindV1,
    ReceiptOrderEvidenceV1, ReceiptOrderLineV1, ReceiptPromotionId, ReceiptPromotionPort,
    ReceiptPromotionV1, ReceiptPurchaseUnitAuthorityV1, ReceiptPurchaseUnitExclusionReasonV1,
    ReceiptPurchaseUnitExclusionV1, ReceiptPurchaseUnitFieldProvenanceV1, ReceiptPurchaseUnitId,
    ReceiptPurchaseUnitProvenanceV1, ReceiptPurchaseUnitSnapshotV1,
    ReceiptPurchaseUnitStatusFilterV1, ReceiptPurchaseUnitStatusV1, ReceiptPurchaseUnitV1,
    ReceiptPurchaseUnitValuesV1, ReceiptReviewActionV1, ReceiptSourceAuthorityId, ReplayStatusV1,
    Sha256Digest, SourceId, Validate, SCHEMA_VERSION_V1,
};

const LIST_CURSOR_KIND: &str = "receipt-purchase-units-v1";
const PROMOTE_COMMAND: &str = "promote_receipt_purchase_unit_v1";

#[derive(Clone)]
enum ProjectionEntry {
    Unit(ReceiptPurchaseUnitV1),
    Exclusion(ReceiptPurchaseUnitExclusionV1),
}

#[derive(Clone)]
struct Projection {
    units: Vec<ReceiptPurchaseUnitV1>,
    exclusions: Vec<ReceiptPurchaseUnitExclusionV1>,
}

impl ReceiptPromotionPort for Database {
    fn list_receipt_purchase_units(
        &self,
        request: &ListReceiptPurchaseUnitsV1Request,
    ) -> wardrobe_core::ReceiptPortResult<ListReceiptPurchaseUnitsV1Response> {
        self.list_receipt_purchase_units_impl(request)
            .map_err(receipt_port_error)
    }

    fn promote_receipt_purchase_unit(
        &self,
        request: &PromoteReceiptPurchaseUnitV1Request,
    ) -> wardrobe_core::ReceiptPortResult<PromoteReceiptPurchaseUnitV1Response> {
        self.promote_receipt_purchase_unit_impl(request)
            .map_err(receipt_port_error)
    }
}

impl Database {
    fn list_receipt_purchase_units_impl(
        &self,
        request: &ListReceiptPurchaseUnitsV1Request,
    ) -> PlatformResult<ListReceiptPurchaseUnitsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_purchase_unit_list"))?;
        let connection = self.connection()?;
        let snapshot = purchase_unit_snapshot(&connection)?;
        let projection = project_purchase_units(&connection, request.source_id)?;
        let mut entries = projection
            .units
            .iter()
            .filter(|unit| {
                request
                    .status
                    .is_none_or(|status| unit.status.filter() == status)
            })
            .cloned()
            .map(ProjectionEntry::Unit)
            .collect::<Vec<_>>();
        if request.status != Some(ReceiptPurchaseUnitStatusFilterV1::Promoted) {
            entries.extend(
                projection
                    .exclusions
                    .iter()
                    .cloned()
                    .map(ProjectionEntry::Exclusion),
            );
        }
        entries.sort_by(|left, right| entry_key(left).cmp(&entry_key(right)));
        let offset = parse_list_cursor(
            request.cursor.as_ref(),
            &snapshot,
            request.source_id,
            request.status,
        )?;
        let page_end = offset
            .saturating_add(usize::from(request.limit))
            .min(entries.len());
        let page = entries
            .get(offset..page_end)
            .ok_or(PlatformError::InvalidInput("receipt_purchase_unit_cursor"))?;
        let units = page
            .iter()
            .filter_map(|entry| match entry {
                ProjectionEntry::Unit(unit) => Some(unit.clone()),
                ProjectionEntry::Exclusion(_) => None,
            })
            .collect::<Vec<_>>();
        let exclusions = page
            .iter()
            .filter_map(|entry| match entry {
                ProjectionEntry::Unit(_) => None,
                ProjectionEntry::Exclusion(exclusion) => Some(exclusion.clone()),
            })
            .collect::<Vec<_>>();
        let next_cursor = (page_end < entries.len())
            .then(|| make_list_cursor(&snapshot, request.source_id, request.status, page_end))
            .transpose()?;
        let total_count = projection
            .units
            .iter()
            .filter(|unit| {
                request
                    .status
                    .is_none_or(|status| unit.status.filter() == status)
            })
            .count() as u64;
        let total_exclusion_count =
            if request.status == Some(ReceiptPurchaseUnitStatusFilterV1::Promoted) {
                0
            } else {
                projection.exclusions.len() as u64
            };
        let response = ListReceiptPurchaseUnitsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            units,
            exclusions,
            total_count,
            total_exclusion_count,
            snapshot,
            next_cursor,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_list_response"))?;
        Ok(response)
    }

    fn promote_receipt_purchase_unit_impl(
        &self,
        request: &PromoteReceiptPurchaseUnitV1Request,
    ) -> PlatformResult<PromoteReceiptPurchaseUnitV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_purchase_unit_promotion"))?;
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<_, PromoteReceiptPurchaseUnitV1Response>(
            &transaction,
            PROMOTE_COMMAND,
            request,
        )? {
            response
                .validate()
                .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_replay"))?;
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }

        let snapshot = purchase_unit_snapshot(&transaction)?;
        if snapshot.catalog_revision != request.expected_catalog_revision {
            return Err(PlatformError::Conflict("catalog_revision"));
        }
        let projection = project_purchase_units(&transaction, None)?;
        let current = projection
            .units
            .into_iter()
            .find(|unit| unit.purchase_unit_id == request.purchase_unit_id)
            .ok_or_else(|| {
                if projection.exclusions.iter().any(|exclusion| {
                    exclusion.order_line_id.is_some_and(|line_id| {
                        exclusion.unit_ordinal.is_some_and(|ordinal| {
                            ReceiptPurchaseUnitId::derive_v1(line_id, ordinal).ok()
                                == Some(request.purchase_unit_id)
                        })
                    })
                }) {
                    PlatformError::Conflict("receipt_purchase_unit_ineligible")
                } else {
                    PlatformError::InvalidInput("receipt_purchase_unit")
                }
            })?;
        if !matches!(current.status, ReceiptPurchaseUnitStatusV1::Available)
            || current.purchase_unit_revision != request.expected_purchase_unit_revision
            || current.unit_snapshot_sha256 != request.expected_unit_snapshot_sha256
            || current.authority.authority_id != request.expected_authority_id
            || current.authority.authority_revision != request.expected_authority_revision
            || current.authority.receipt_revision != request.expected_receipt_revision
            || current.authority.review_decision_id != request.expected_review_decision_id
        {
            return Err(PlatformError::Conflict("receipt_purchase_unit_changed"));
        }
        if transaction
            .query_row(
                "SELECT 1 FROM receipt_purchase_unit_deletions
                 WHERE purchase_unit_id=?1",
                [request.purchase_unit_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(PlatformError::Conflict("receipt_purchase_unit_deleted"));
        }
        if transaction
            .query_row(
                "SELECT 1 FROM receipt_purchase_unit_promotions
                 WHERE order_line_id=?1 AND unit_ordinal=?2",
                params![
                    current.order_line_id.to_string(),
                    i64::from(current.unit_ordinal)
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(PlatformError::Conflict("receipt_purchase_unit_promoted"));
        }

        let new_catalog_revision =
            advance_catalog_revision(&transaction, request.expected_catalog_revision)?;
        let new_evidence_generation = advance_evidence_generation(&transaction)?;
        let request_id = request.request_id.to_string();
        let item_id = parse_item_id(&stable_id("receipt-promotion-item", &request_id))?;
        let evidence_id = parse_evidence_id(&stable_id("receipt-promotion-evidence", &request_id))?;
        let decision_id = parse_decision_id(&stable_id("receipt-promotion-decision", &request_id))?;
        let promotion_id = parse_promotion_id(&stable_id("receipt-promotion", &request_id))?;
        let authority_snapshot_id = parse_authority_snapshot_id(&stable_id(
            "receipt-authority-snapshot",
            &format!(
                "{}:{}",
                current.authority.authority_id, current.order_line_id
            ),
        ))?;

        transaction.execute(
            "INSERT OR IGNORE INTO receipt_authority_snapshots(
                authority_snapshot_id, authority_id, local_source_id,
                order_evidence_id, order_line_id, review_decision_id,
                review_action, receipt_revision, authority_revision,
                values_json, provenance_json, snapshot_sha256, created_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                authority_snapshot_id.to_string(),
                current.authority.authority_id.to_string(),
                current.authority.source_id.to_string(),
                current.authority.order_evidence_id.to_string(),
                current.order_line_id.to_string(),
                current.authority.review_decision_id.to_string(),
                review_action_db(current.authority.review_action),
                current.authority.receipt_revision as i64,
                current.authority.authority_revision as i64,
                serde_json::to_string(&current.values)?,
                serde_json::to_string(&current.provenance)?,
                current.unit_snapshot_sha256.as_str(),
                now_ms,
            ],
        )?;
        let stored_snapshot_hash: String = transaction.query_row(
            "SELECT snapshot_sha256 FROM receipt_authority_snapshots
             WHERE authority_snapshot_id=?1",
            [authority_snapshot_id.to_string()],
            |row| row.get(0),
        )?;
        if stored_snapshot_hash != current.unit_snapshot_sha256.as_str() {
            return Err(PlatformError::Conflict("receipt_authority_snapshot"));
        }
        transaction.execute(
            "INSERT INTO catalog_items(
                item_id,display_name,attributes_json,active,
                created_revision,updated_revision
             ) VALUES (?1,?2,?3,1,?4,?4)",
            params![
                item_id.to_string(),
                request.attributes.display_name,
                serde_json::to_string(&request.attributes)?,
                new_catalog_revision as i64,
            ],
        )?;
        transaction.execute(
            "INSERT INTO evidence(
                evidence_id,source_id,part_id,evidence_kind,state,
                created_at_ms,updated_at_ms
             ) VALUES (?1,?2,NULL,'receipt_purchase_unit','assigned',?3,?3)",
            params![
                evidence_id.to_string(),
                current.authority.source_id.to_string(),
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO item_evidence(item_id,evidence_id,assigned_revision)
             VALUES (?1,?2,?3)",
            params![
                item_id.to_string(),
                evidence_id.to_string(),
                new_catalog_revision as i64
            ],
        )?;
        transaction.execute(
            "INSERT INTO catalog_decisions(
                decision_id,request_id,decision_kind,catalog_revision,
                forward_json,inverse_json,compensates_decision_id,created_at_ms
             ) VALUES (?1,?2,'promote_receipt_purchase_unit',?3,?4,?5,NULL,?6)",
            params![
                decision_id.to_string(),
                request_id,
                new_catalog_revision as i64,
                serde_json::to_string(request)?,
                r#"{"kind":"irreversible_receipt_purchase_unit_promotion"}"#,
                now_ms,
            ],
        )?;
        for (kind, id) in [
            ("item", item_id.to_string()),
            ("evidence", evidence_id.to_string()),
        ] {
            transaction.execute(
                "INSERT INTO decision_entities(decision_id,entity_kind,entity_id)
                 VALUES (?1,?2,?3)",
                params![decision_id.to_string(), kind, id],
            )?;
        }

        let promoted_at = timestamp_from_ms(now_ms)?;
        let authority_snapshot = ReceiptAuthoritySnapshotV1 {
            authority_snapshot_id,
            authority: current.authority.clone(),
            order_line_id: current.order_line_id,
            values: current.values.clone(),
            provenance: current.provenance.clone(),
            snapshot_sha256: current.unit_snapshot_sha256.clone(),
            created_at: promoted_at.clone(),
        };
        let promotion = ReceiptPromotionV1 {
            promotion_id,
            purchase_unit_id: current.purchase_unit_id,
            order_line_id: current.order_line_id,
            unit_ordinal: current.unit_ordinal,
            item_id,
            evidence_id,
            decision_id,
            authority_snapshot_id,
            request_id: request.request_id,
            promoted_at,
        };
        let decision = DecisionSnapshotV1 {
            decision_id,
            kind: DecisionKindV1::PromoteReceiptPurchaseUnit,
            affected_item_ids: vec![item_id],
            affected_evidence_ids: vec![evidence_id],
            compensates_decision_id: None,
            reversible: false,
        };
        let item = CatalogItemV1 {
            item_id,
            attributes: request.attributes.clone(),
            evidence_ids: vec![evidence_id],
            last_decision_id: decision_id,
        };
        let mut unit = current;
        unit.purchase_unit_revision = unit
            .purchase_unit_revision
            .checked_add(1)
            .ok_or(PlatformError::Corrupt("receipt_purchase_unit_revision"))?;
        unit.catalog_revision = new_catalog_revision;
        unit.evidence_generation = new_evidence_generation;
        unit.status = ReceiptPurchaseUnitStatusV1::Promoted {
            promotion_id,
            item_id,
            evidence_id,
            decision_id,
        };
        let response = PromoteReceiptPurchaseUnitV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            unit,
            item,
            authority_snapshot,
            promotion,
            decision,
            new_catalog_revision,
            new_evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_response"))?;
        store_receipt(&transaction, PROMOTE_COMMAND, request, &response, now_ms)?;
        transaction.execute(
            "INSERT INTO receipt_purchase_unit_promotions(
                promotion_id,purchase_unit_id,identity_version,
                order_line_id,unit_ordinal,authoritative_quantity,
                purchase_unit_revision,unit_snapshot_sha256,
                authority_snapshot_id,item_id,evidence_id,decision_id,request_id,
                catalog_revision,evidence_generation,created_at_ms
             ) VALUES (?1,?2,'receipt-purchase-unit-v1',?3,?4,?5,?6,?7,?8,
                       ?9,?10,?11,?12,?13,?14,?15)",
            params![
                promotion_id.to_string(),
                request.purchase_unit_id.to_string(),
                response.unit.order_line_id.to_string(),
                i64::from(response.unit.unit_ordinal),
                response.unit.authoritative_quantity as i64,
                response.unit.purchase_unit_revision as i64,
                response.unit.unit_snapshot_sha256.as_str(),
                authority_snapshot_id.to_string(),
                item_id.to_string(),
                evidence_id.to_string(),
                decision_id.to_string(),
                request.request_id.to_string(),
                new_catalog_revision as i64,
                new_evidence_generation as i64,
                now_ms,
            ],
        )?;
        for (kind, id) in [
            ("purchase_unit", request.purchase_unit_id.to_string()),
            ("authority_snapshot", authority_snapshot_id.to_string()),
            ("promotion", promotion_id.to_string()),
        ] {
            transaction.execute(
                "INSERT INTO receipt_command_entities(request_id,entity_kind,entity_id)
                 VALUES (?1,?2,?3)",
                params![request.request_id.to_string(), kind, id],
            )?;
        }
        transaction.commit()?;
        Ok(response)
    }
}

fn project_purchase_units(
    connection: &Connection,
    source_filter: Option<SourceId>,
) -> PlatformResult<Projection> {
    let snapshot = purchase_unit_snapshot(connection)?;
    let mut units = Vec::new();
    let mut exclusions = Vec::new();
    let mut visible_unit_ids = BTreeSet::new();
    append_review_required_exclusions(connection, source_filter, &mut exclusions)?;
    let sql = if source_filter.is_some() {
        "SELECT local_source_id,authority_id,order_evidence_id,
                review_decision_id,receipt_revision,authority_revision
         FROM receipt_source_authority_heads WHERE local_source_id=?1
         ORDER BY local_source_id"
    } else {
        "SELECT local_source_id,authority_id,order_evidence_id,
                review_decision_id,receipt_revision,authority_revision
         FROM receipt_source_authority_heads
         WHERE ?1 IS NULL ORDER BY local_source_id"
    };
    let source_parameter = source_filter.map(|value| value.to_string());
    let mut statement = connection.prepare(sql)?;
    let authorities = statement
        .query_map([source_parameter], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (
        source_id,
        authority_id,
        order_id,
        review_decision_id,
        receipt_revision,
        authority_revision,
    ) in authorities
    {
        let order = load_order(connection, &order_id)?;
        let review_head = order
            .review_head
            .as_ref()
            .ok_or(PlatformError::Corrupt("receipt_authority_review"))?;
        if review_head.decision.decision_id.to_string() != review_decision_id {
            return Err(PlatformError::Corrupt("receipt_authority_review"));
        }
        let source = parse_source_id(&source_id)?;
        let order_evidence_id = order.order_evidence_id;
        let authority = ReceiptPurchaseUnitAuthorityV1 {
            authority_id: parse_authority_id(&authority_id)?,
            source_id: source,
            order_evidence_id,
            review_decision_id: review_head.decision.decision_id,
            review_action: review_head.decision.action,
            authority_revision: u64::try_from(authority_revision)
                .map_err(|_| PlatformError::Corrupt("receipt_authority_revision"))?,
            receipt_revision: u64::try_from(receipt_revision)
                .map_err(|_| PlatformError::Corrupt("receipt_revision"))?,
        };
        if !matches!(
            authority.review_action,
            ReceiptReviewActionV1::Confirm | ReceiptReviewActionV1::Correct
        ) {
            let reason = if authority.review_action == ReceiptReviewActionV1::Reject {
                ReceiptPurchaseUnitExclusionReasonV1::Rejected
            } else {
                ReceiptPurchaseUnitExclusionReasonV1::Deferred
            };
            exclusions.extend(
                order
                    .line_items
                    .iter()
                    .map(|line| ReceiptPurchaseUnitExclusionV1 {
                        source_id: source,
                        order_evidence_id: Some(order_evidence_id),
                        order_line_id: Some(line.order_line_id),
                        unit_ordinal: None,
                        reason,
                    }),
            );
            continue;
        }
        let authority_changed =
            source_has_prior_authority_state(connection, &source_id, &authority_id, &order_id)?;
        let corrected = review_head.decision.corrected_order.as_ref();
        for (index, line) in order.line_items.iter().enumerate() {
            let effective_event = corrected
                .and_then(|order| order.line_items.get(index))
                .map_or(line.event_kind.value, |line| line.event_kind);
            let effective_quantity = corrected
                .and_then(|order| order.line_items.get(index))
                .map_or(line.quantity.value, |line| line.quantity);
            if effective_event.is_none() {
                exclusions.push(ReceiptPurchaseUnitExclusionV1 {
                    source_id: source,
                    order_evidence_id: Some(order_evidence_id),
                    order_line_id: Some(line.order_line_id),
                    unit_ordinal: None,
                    reason: ReceiptPurchaseUnitExclusionReasonV1::UnknownEventKind,
                });
                continue;
            }
            if effective_quantity.is_none() {
                exclusions.push(ReceiptPurchaseUnitExclusionV1 {
                    source_id: source,
                    order_evidence_id: Some(order_evidence_id),
                    order_line_id: Some(line.order_line_id),
                    unit_ordinal: None,
                    reason: ReceiptPurchaseUnitExclusionReasonV1::UnknownQuantity,
                });
                continue;
            }
            let (values, provenance) = effective_values(
                &order,
                line,
                corrected,
                index,
                review_head.decision.decision_id,
            )?;
            if authority_changed {
                exclusions.push(ReceiptPurchaseUnitExclusionV1 {
                    source_id: source,
                    order_evidence_id: Some(order_evidence_id),
                    order_line_id: Some(line.order_line_id),
                    unit_ordinal: None,
                    reason:
                        ReceiptPurchaseUnitExclusionReasonV1::AuthorityChangedResolutionRequired,
                });
                continue;
            }
            if values.event_kind != ReceiptEventKindV1::Purchase {
                exclusions.push(ReceiptPurchaseUnitExclusionV1 {
                    source_id: source,
                    order_evidence_id: Some(order_evidence_id),
                    order_line_id: Some(line.order_line_id),
                    unit_ordinal: None,
                    reason: ReceiptPurchaseUnitExclusionReasonV1::NonPurchase,
                });
                continue;
            }
            for unit_ordinal in 0..u32::try_from(values.quantity)
                .map_err(|_| PlatformError::Corrupt("receipt_quantity"))?
            {
                let purchase_unit_id =
                    ReceiptPurchaseUnitId::derive_v1(line.order_line_id, unit_ordinal)
                        .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_id"))?;
                if connection
                    .query_row(
                        "SELECT 1 FROM receipt_purchase_unit_deletions
                         WHERE purchase_unit_id=?1",
                        [purchase_unit_id.to_string()],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some()
                {
                    exclusions.push(ReceiptPurchaseUnitExclusionV1 {
                        source_id: source,
                        order_evidence_id: Some(order_evidence_id),
                        order_line_id: Some(line.order_line_id),
                        unit_ordinal: Some(unit_ordinal),
                        reason: ReceiptPurchaseUnitExclusionReasonV1::UserDeleted,
                    });
                    continue;
                }
                let digest =
                    unit_snapshot_digest(line.order_line_id, &values, &provenance, &authority)?;
                let status = load_promotion_status(
                    connection,
                    &line.order_line_id.to_string(),
                    unit_ordinal,
                )?
                .unwrap_or(ReceiptPurchaseUnitStatusV1::Available);
                let purchase_unit_revision = load_promotion_revision(
                    connection,
                    &line.order_line_id.to_string(),
                    unit_ordinal,
                )?
                .unwrap_or(authority.authority_revision);
                let unit = ReceiptPurchaseUnitV1 {
                    purchase_unit_id,
                    order_line_id: line.order_line_id,
                    unit_ordinal,
                    authoritative_quantity: values.quantity,
                    values: values.clone(),
                    provenance: provenance.clone(),
                    authority: authority.clone(),
                    purchase_unit_revision,
                    unit_snapshot_sha256: digest,
                    catalog_revision: snapshot.catalog_revision,
                    evidence_generation: snapshot.evidence_generation,
                    status,
                };
                unit.validate()
                    .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit"))?;
                visible_unit_ids.insert(unit.purchase_unit_id.to_string());
                units.push(unit);
            }
        }
    }
    load_historical_promotions(
        connection,
        source_filter,
        &snapshot,
        &visible_unit_ids,
        &mut units,
    )?;
    Ok(Projection { units, exclusions })
}

fn append_review_required_exclusions(
    connection: &Connection,
    source_filter: Option<SourceId>,
    exclusions: &mut Vec<ReceiptPurchaseUnitExclusionV1>,
) -> PlatformResult<()> {
    let source = source_filter.map(|value| value.to_string());
    let mut statement = connection.prepare(
        "SELECT parse.source_id, receipt_order.order_evidence_id
         FROM receipt_orders receipt_order
         JOIN receipt_extraction_runs run ON run.run_id=receipt_order.run_id
         JOIN receipt_parses parse ON parse.parse_id=run.parse_id
         WHERE run.status='succeeded'
           AND (?1 IS NULL OR parse.source_id=?1)
           AND NOT EXISTS (
               SELECT 1 FROM receipt_source_authority_heads authority
               WHERE authority.local_source_id=parse.source_id
           )
           AND run.run_id=(
               SELECT latest.run_id
               FROM receipt_extraction_runs latest
               JOIN receipt_parses latest_parse
                 ON latest_parse.parse_id=latest.parse_id
               WHERE latest_parse.source_id=parse.source_id
                 AND latest.status='succeeded'
               ORDER BY latest.created_at_ms DESC,latest.run_id DESC
               LIMIT 1
           )
         ORDER BY parse.source_id",
    )?;
    let rows = statement
        .query_map([source], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (source_id, order_id) in rows {
        let source_id = parse_source_id(&source_id)?;
        let order = load_order(connection, &order_id)?;
        exclusions.extend(
            order
                .line_items
                .iter()
                .map(|line| ReceiptPurchaseUnitExclusionV1 {
                    source_id,
                    order_evidence_id: Some(order.order_evidence_id),
                    order_line_id: Some(line.order_line_id),
                    unit_ordinal: None,
                    reason: ReceiptPurchaseUnitExclusionReasonV1::ReviewRequired,
                }),
        );
    }
    Ok(())
}

fn effective_values(
    order: &ReceiptOrderEvidenceV1,
    line: &ReceiptOrderLineV1,
    corrected: Option<&CorrectedReceiptOrderV1>,
    index: usize,
    review_decision_id: wardrobe_core::ReceiptReviewDecisionId,
) -> PlatformResult<(ReceiptPurchaseUnitValuesV1, ReceiptPurchaseUnitProvenanceV1)> {
    if let Some(corrected) = corrected {
        let corrected_line = corrected
            .line_items
            .get(index)
            .filter(|candidate| candidate.order_line_id == line.order_line_id)
            .ok_or(PlatformError::Corrupt("receipt_corrected_line"))?;
        let values = ReceiptPurchaseUnitValuesV1 {
            merchant: corrected.merchant.clone(),
            order_identifier: corrected.order_identifier.clone(),
            purchase_date: corrected.purchase_date.clone(),
            currency: corrected.currency.clone(),
            description: corrected_line.description.clone(),
            event_kind: corrected_line
                .event_kind
                .ok_or(PlatformError::InvalidInput("receipt_event_kind"))?,
            quantity: corrected_line
                .quantity
                .ok_or(PlatformError::InvalidInput("receipt_quantity"))?,
            unit_price_minor: corrected_line.unit_price_minor,
            brand: corrected_line.variant.brand.clone(),
            sku: corrected_line.variant.sku.clone(),
            size: corrected_line.variant.size.clone(),
            color: corrected_line.variant.color.clone(),
        };
        let correction =
            || ReceiptPurchaseUnitFieldProvenanceV1::UserCorrection { review_decision_id };
        return Ok((
            values,
            ReceiptPurchaseUnitProvenanceV1 {
                merchant: correction(),
                order_identifier: correction(),
                purchase_date: correction(),
                currency: correction(),
                description: correction(),
                event_kind: correction(),
                quantity: correction(),
                unit_price_minor: correction(),
                brand: correction(),
                sku: correction(),
                size: correction(),
                color: correction(),
            },
        ));
    }
    let values = ReceiptPurchaseUnitValuesV1 {
        merchant: order.merchant.value.clone(),
        order_identifier: order.order_identifier.value.clone(),
        purchase_date: order.purchase_date.value.clone(),
        currency: order.currency.value.clone(),
        description: line.description.value.clone(),
        event_kind: line
            .event_kind
            .value
            .ok_or(PlatformError::InvalidInput("receipt_event_kind"))?,
        quantity: line
            .quantity
            .value
            .ok_or(PlatformError::InvalidInput("receipt_quantity"))?,
        unit_price_minor: line.unit_price_minor.value,
        brand: line.variant.brand.value.clone(),
        sku: line.variant.sku.value.clone(),
        size: line.variant.size.value.clone(),
        color: line.variant.color.value.clone(),
    };
    Ok((
        values,
        ReceiptPurchaseUnitProvenanceV1 {
            merchant: citation_provenance(&order.merchant.value, &order.merchant.citations),
            order_identifier: citation_provenance(
                &order.order_identifier.value,
                &order.order_identifier.citations,
            ),
            purchase_date: citation_provenance(
                &order.purchase_date.value,
                &order.purchase_date.citations,
            ),
            currency: citation_provenance(&order.currency.value, &order.currency.citations),
            description: citation_provenance(&line.description.value, &line.description.citations),
            event_kind: citation_provenance(&line.event_kind.value, &line.event_kind.citations),
            quantity: citation_provenance(&line.quantity.value, &line.quantity.citations),
            unit_price_minor: citation_provenance(
                &line.unit_price_minor.value,
                &line.unit_price_minor.citations,
            ),
            brand: citation_provenance(&line.variant.brand.value, &line.variant.brand.citations),
            sku: citation_provenance(&line.variant.sku.value, &line.variant.sku.citations),
            size: citation_provenance(&line.variant.size.value, &line.variant.size.citations),
            color: citation_provenance(&line.variant.color.value, &line.variant.color.citations),
        },
    ))
}

fn citation_provenance<T>(
    value: &Option<T>,
    citations: &[wardrobe_core::FragmentCitationV1],
) -> ReceiptPurchaseUnitFieldProvenanceV1 {
    if value.is_some() {
        ReceiptPurchaseUnitFieldProvenanceV1::ReceiptCitations {
            citations: citations.to_vec(),
        }
    } else {
        ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField
    }
}

fn source_has_prior_authority_state(
    connection: &Connection,
    source_id: &str,
    authority_id: &str,
    order_id: &str,
) -> PlatformResult<bool> {
    let count: i64 = connection.query_row(
        "SELECT
            (SELECT COUNT(*)
             FROM receipt_purchase_unit_promotions promotion
             JOIN receipt_authority_snapshots snapshot
               ON snapshot.authority_snapshot_id=promotion.authority_snapshot_id
             WHERE snapshot.local_source_id=?1
               AND (snapshot.authority_id<>?2 OR snapshot.order_evidence_id<>?3))
          + (SELECT COUNT(*) FROM receipt_purchase_unit_deletions deletion
             WHERE deletion.local_source_id=?1
               AND (deletion.authority_id<>?2 OR deletion.order_evidence_id<>?3))",
        params![source_id, authority_id, order_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn load_promotion_status(
    connection: &Connection,
    line_id: &str,
    ordinal: u32,
) -> PlatformResult<Option<ReceiptPurchaseUnitStatusV1>> {
    connection
        .query_row(
            "SELECT promotion_id,item_id,evidence_id,decision_id
             FROM receipt_purchase_unit_promotions
             WHERE order_line_id=?1 AND unit_ordinal=?2",
            params![line_id, i64::from(ordinal)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(ReceiptPurchaseUnitStatusV1::Promoted {
                promotion_id: parse_promotion_id(&row.0)?,
                item_id: parse_item_id(&row.1)?,
                evidence_id: parse_evidence_id(&row.2)?,
                decision_id: parse_decision_id(&row.3)?,
            })
        })
        .transpose()
}

fn load_promotion_revision(
    connection: &Connection,
    line_id: &str,
    ordinal: u32,
) -> PlatformResult<Option<u64>> {
    connection
        .query_row(
            "SELECT purchase_unit_revision
             FROM receipt_purchase_unit_promotions
             WHERE order_line_id=?1 AND unit_ordinal=?2",
            params![line_id, i64::from(ordinal)],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_revision"))
        })
        .transpose()
}

fn load_historical_promotions(
    connection: &Connection,
    source_filter: Option<SourceId>,
    snapshot: &ReceiptPurchaseUnitSnapshotV1,
    visible: &BTreeSet<String>,
    units: &mut Vec<ReceiptPurchaseUnitV1>,
) -> PlatformResult<()> {
    let source = source_filter.map(|value| value.to_string());
    let mut statement = connection.prepare(
        "SELECT promotion.purchase_unit_id,promotion.order_line_id,
                promotion.unit_ordinal,promotion.authoritative_quantity,
                promotion.purchase_unit_revision,promotion.unit_snapshot_sha256,
                promotion.promotion_id,promotion.item_id,promotion.evidence_id,
                promotion.decision_id,
                snapshot.authority_id,snapshot.local_source_id,
                snapshot.order_evidence_id,snapshot.review_decision_id,
                snapshot.review_action,snapshot.authority_revision,
                snapshot.receipt_revision,snapshot.values_json,
                snapshot.provenance_json
         FROM receipt_purchase_unit_promotions promotion
         JOIN receipt_authority_snapshots snapshot
           ON snapshot.authority_snapshot_id=promotion.authority_snapshot_id
         WHERE (?1 IS NULL OR snapshot.local_source_id=?1)
         ORDER BY snapshot.local_source_id,promotion.order_line_id,
                  promotion.unit_ordinal",
    )?;
    let rows = statement
        .query_map([source], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, i64>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for row in rows {
        if visible.contains(&row.0) {
            continue;
        }
        let unit = ReceiptPurchaseUnitV1 {
            purchase_unit_id: parse_purchase_unit_id(&row.0)?,
            order_line_id: parse_line_id(&row.1)?,
            unit_ordinal: u32::try_from(row.2)
                .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_ordinal"))?,
            authoritative_quantity: u64::try_from(row.3)
                .map_err(|_| PlatformError::Corrupt("receipt_quantity"))?,
            purchase_unit_revision: u64::try_from(row.4)
                .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_revision"))?,
            unit_snapshot_sha256: parse_digest(&row.5)?,
            values: serde_json::from_str(&row.17)?,
            provenance: serde_json::from_str(&row.18)?,
            authority: ReceiptPurchaseUnitAuthorityV1 {
                authority_id: parse_authority_id(&row.10)?,
                source_id: parse_source_id(&row.11)?,
                order_evidence_id: parse_order_id(&row.12)?,
                review_decision_id: parse_review_id(&row.13)?,
                review_action: review_action_from_db(&row.14)?,
                authority_revision: u64::try_from(row.15)
                    .map_err(|_| PlatformError::Corrupt("receipt_authority_revision"))?,
                receipt_revision: u64::try_from(row.16)
                    .map_err(|_| PlatformError::Corrupt("receipt_revision"))?,
            },
            catalog_revision: snapshot.catalog_revision,
            evidence_generation: snapshot.evidence_generation,
            status: ReceiptPurchaseUnitStatusV1::Promoted {
                promotion_id: parse_promotion_id(&row.6)?,
                item_id: parse_item_id(&row.7)?,
                evidence_id: parse_evidence_id(&row.8)?,
                decision_id: parse_decision_id(&row.9)?,
            },
        };
        unit.validate()
            .map_err(|_| PlatformError::Corrupt("historical_receipt_purchase_unit"))?;
        units.push(unit);
    }
    Ok(())
}

fn unit_snapshot_digest(
    order_line_id: wardrobe_core::ReceiptOrderLineId,
    values: &ReceiptPurchaseUnitValuesV1,
    provenance: &ReceiptPurchaseUnitProvenanceV1,
    authority: &ReceiptPurchaseUnitAuthorityV1,
) -> PlatformResult<Sha256Digest> {
    #[derive(Serialize)]
    struct Snapshot<'a> {
        identity_version: &'static str,
        order_line_id: wardrobe_core::ReceiptOrderLineId,
        values: &'a ReceiptPurchaseUnitValuesV1,
        provenance: &'a ReceiptPurchaseUnitProvenanceV1,
        authority: &'a ReceiptPurchaseUnitAuthorityV1,
    }
    Ok(Sha256Digest::from_bytes(&serde_json::to_vec(&Snapshot {
        identity_version: wardrobe_core::RECEIPT_PURCHASE_UNIT_IDENTITY_VERSION_V1,
        order_line_id,
        values,
        provenance,
        authority,
    })?))
}

fn purchase_unit_snapshot(
    connection: &Connection,
) -> PlatformResult<ReceiptPurchaseUnitSnapshotV1> {
    let (receipt, evidence, catalog): (i64, i64, i64) = connection.query_row(
        "SELECT receipt_revision,evidence_generation,catalog_revision
         FROM revision_state WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(ReceiptPurchaseUnitSnapshotV1 {
        receipt_revision: u64::try_from(receipt)
            .map_err(|_| PlatformError::Corrupt("receipt_revision"))?,
        evidence_generation: u64::try_from(evidence)
            .map_err(|_| PlatformError::Corrupt("evidence_generation"))?,
        catalog_revision: u64::try_from(catalog)
            .map_err(|_| PlatformError::Corrupt("catalog_revision"))?,
    })
}

fn make_list_cursor(
    snapshot: &ReceiptPurchaseUnitSnapshotV1,
    source: Option<SourceId>,
    status: Option<ReceiptPurchaseUnitStatusFilterV1>,
    offset: usize,
) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!(
        "{LIST_CURSOR_KIND}.{}.{}.{}.{}.{}.{}",
        snapshot.receipt_revision,
        snapshot.evidence_generation,
        snapshot.catalog_revision,
        source.map_or_else(|| "*".to_owned(), |value| value.to_string()),
        status.map_or("*", status_db),
        offset
    ))
    .map_err(|_| PlatformError::Corrupt("receipt_purchase_unit_cursor"))
}

fn parse_list_cursor(
    cursor: Option<&PageCursorV1>,
    snapshot: &ReceiptPurchaseUnitSnapshotV1,
    source: Option<SourceId>,
    status: Option<ReceiptPurchaseUnitStatusFilterV1>,
) -> PlatformResult<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let pieces = cursor.as_str().split('.').collect::<Vec<_>>();
    if pieces.len() != 7
        || pieces[0] != LIST_CURSOR_KIND
        || pieces[1].parse::<u64>().ok() != Some(snapshot.receipt_revision)
        || pieces[2].parse::<u64>().ok() != Some(snapshot.evidence_generation)
        || pieces[3].parse::<u64>().ok() != Some(snapshot.catalog_revision)
        || pieces[4]
            != source
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("*")
        || pieces[5] != status.map(status_db).unwrap_or("*")
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    pieces[6]
        .parse()
        .map_err(|_| PlatformError::InvalidInput("receipt_purchase_unit_cursor"))
}

fn entry_key(entry: &ProjectionEntry) -> String {
    match entry {
        ProjectionEntry::Unit(unit) => format!(
            "{}:{}:{:05}:0",
            unit.authority.source_id, unit.order_line_id, unit.unit_ordinal
        ),
        ProjectionEntry::Exclusion(exclusion) => format!(
            "{}:{}:{:05}:1",
            exclusion.source_id,
            exclusion
                .order_line_id
                .map_or_else(|| "*".to_owned(), |value| value.to_string()),
            exclusion.unit_ordinal.unwrap_or(0)
        ),
    }
}

fn status_db(status: ReceiptPurchaseUnitStatusFilterV1) -> &'static str {
    match status {
        ReceiptPurchaseUnitStatusFilterV1::Available => "available",
        ReceiptPurchaseUnitStatusFilterV1::Promoted => "promoted",
    }
}

fn advance_catalog_revision(transaction: &Transaction<'_>, expected: u64) -> PlatformResult<u64> {
    transaction
        .query_row(
            "UPDATE revision_state SET catalog_revision=catalog_revision+1
             WHERE singleton=1 AND catalog_revision=?1
             RETURNING catalog_revision",
            [expected as i64],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| value as u64)
        .ok_or(PlatformError::Conflict("catalog_revision"))
}

fn advance_evidence_generation(transaction: &Transaction<'_>) -> PlatformResult<u64> {
    transaction
        .query_row(
            "UPDATE revision_state SET evidence_generation=evidence_generation+1
             WHERE singleton=1 RETURNING evidence_generation",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value as u64)
        .map_err(Into::into)
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
            "SELECT command_name,envelope_hash,response_json
             FROM command_receipts WHERE request_id=?1",
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
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO command_receipts(
            request_id,command_name,envelope_hash,response_json,created_at_ms
         ) VALUES (?1,?2,?3,?4,?5)",
        params![
            request_id_from_json(request)?,
            command,
            envelope_hash(request)?,
            serde_json::to_string(response)?,
            now_ms
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

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    let parsed = Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(PlatformError::Corrupt(field));
    }
    Ok(parsed)
}

fn parse_item_id(value: &str) -> PlatformResult<ItemId> {
    ItemId::new(parse_uuid(value, "item_id")?).map_err(|_| PlatformError::Corrupt("item_id"))
}

fn parse_evidence_id(value: &str) -> PlatformResult<EvidenceId> {
    EvidenceId::new(parse_uuid(value, "evidence_id")?)
        .map_err(|_| PlatformError::Corrupt("evidence_id"))
}

fn parse_decision_id(value: &str) -> PlatformResult<DecisionId> {
    DecisionId::new(parse_uuid(value, "decision_id")?)
        .map_err(|_| PlatformError::Corrupt("decision_id"))
}

fn parse_source_id(value: &str) -> PlatformResult<SourceId> {
    SourceId::new(parse_uuid(value, "source_id")?).map_err(|_| PlatformError::Corrupt("source_id"))
}

fn parse_order_id(value: &str) -> PlatformResult<wardrobe_core::ReceiptOrderEvidenceId> {
    wardrobe_core::ReceiptOrderEvidenceId::new(parse_uuid(value, "order_evidence_id")?)
        .map_err(|_| PlatformError::Corrupt("order_evidence_id"))
}

fn parse_line_id(value: &str) -> PlatformResult<wardrobe_core::ReceiptOrderLineId> {
    wardrobe_core::ReceiptOrderLineId::new(parse_uuid(value, "order_line_id")?)
        .map_err(|_| PlatformError::Corrupt("order_line_id"))
}

fn parse_review_id(value: &str) -> PlatformResult<wardrobe_core::ReceiptReviewDecisionId> {
    wardrobe_core::ReceiptReviewDecisionId::new(parse_uuid(value, "review_decision_id")?)
        .map_err(|_| PlatformError::Corrupt("review_decision_id"))
}

fn parse_authority_id(value: &str) -> PlatformResult<ReceiptSourceAuthorityId> {
    ReceiptSourceAuthorityId::new(parse_uuid(value, "authority_id")?)
        .map_err(|_| PlatformError::Corrupt("authority_id"))
}

fn parse_purchase_unit_id(value: &str) -> PlatformResult<ReceiptPurchaseUnitId> {
    ReceiptPurchaseUnitId::new(parse_uuid(value, "purchase_unit_id")?)
        .map_err(|_| PlatformError::Corrupt("purchase_unit_id"))
}

fn parse_promotion_id(value: &str) -> PlatformResult<ReceiptPromotionId> {
    ReceiptPromotionId::new(parse_uuid(value, "promotion_id")?)
        .map_err(|_| PlatformError::Corrupt("promotion_id"))
}

fn parse_authority_snapshot_id(value: &str) -> PlatformResult<ReceiptAuthoritySnapshotId> {
    ReceiptAuthoritySnapshotId::new(parse_uuid(value, "authority_snapshot_id")?)
        .map_err(|_| PlatformError::Corrupt("authority_snapshot_id"))
}

fn parse_digest(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| PlatformError::Corrupt("sha256"))
}

fn review_action_db(action: ReceiptReviewActionV1) -> &'static str {
    match action {
        ReceiptReviewActionV1::Confirm => "confirm",
        ReceiptReviewActionV1::Correct => "correct",
        ReceiptReviewActionV1::Reject => "reject",
        ReceiptReviewActionV1::Defer => "defer",
    }
}

fn review_action_from_db(value: &str) -> PlatformResult<ReceiptReviewActionV1> {
    match value {
        "confirm" => Ok(ReceiptReviewActionV1::Confirm),
        "correct" => Ok(ReceiptReviewActionV1::Correct),
        "reject" => Ok(ReceiptReviewActionV1::Reject),
        "defer" => Ok(ReceiptReviewActionV1::Defer),
        _ => Err(PlatformError::Corrupt("receipt_review_action")),
    }
}

fn timestamp_from_ms(value: i64) -> PlatformResult<String> {
    let nanos = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or(PlatformError::Corrupt("timestamp_range"))?;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| PlatformError::Corrupt("timestamp_range"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("timestamp_format"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

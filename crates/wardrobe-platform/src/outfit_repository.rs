use crate::database::stable_id;
use crate::source_image::verify_source_image;
use crate::{BlobStore, Database, PlatformError, PlatformResult};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use wardrobe_core::{
    BoundedPhotoArtifactBytesV1, CreateManualOutfitV1Request, CreateManualOutfitV1Response,
    EvidenceId, GetOutfitCollageV1Request, GetOutfitCollageV1Response, ItemAttributesV1, ItemId,
    ListOutfitsV1Request, ListOutfitsV1Response, OutfitAssetBindingV1, OutfitAssetStateV1,
    OutfitCollageMemberV1, OutfitId, OutfitMemberV1, OutfitPort, OutfitPortError,
    OutfitPortErrorKind, OutfitPortResult, OutfitV1, PageCursorV1, ReplayStatusV1, Sha256Digest,
    SourceId, Validate, SCHEMA_VERSION_V1,
};

const CREATE_COMMAND: &str = "create_manual_outfit_v1";

impl OutfitPort for Database {
    fn create_manual_outfit(
        &self,
        request: &CreateManualOutfitV1Request,
    ) -> OutfitPortResult<CreateManualOutfitV1Response> {
        self.create_manual_outfit_impl(request)
            .map_err(outfit_port_error)
    }

    fn list_outfits(
        &self,
        request: &ListOutfitsV1Request,
    ) -> OutfitPortResult<ListOutfitsV1Response> {
        self.list_outfits_impl(request).map_err(outfit_port_error)
    }

    fn get_outfit_collage(
        &self,
        request: &GetOutfitCollageV1Request,
    ) -> OutfitPortResult<GetOutfitCollageV1Response> {
        self.get_outfit_collage_impl(request)
            .map_err(outfit_port_error)
    }
}

impl Database {
    fn create_manual_outfit_impl(
        &self,
        request: &CreateManualOutfitV1Request,
    ) -> PlatformResult<CreateManualOutfitV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("outfit_request"))?;
        let envelope_hash = hash_json(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<CreateManualOutfitV1Response>(&transaction, request, &envelope_hash)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }

        let (catalog_revision, outfit_revision): (i64, i64) = transaction.query_row(
            "SELECT catalog_revision, outfit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if catalog_revision != request.expected_catalog_revision as i64
            || outfit_revision != request.expected_outfit_revision as i64
        {
            return Err(PlatformError::Conflict("outfit_revision_changed"));
        }

        let store = BlobStore::new(&self.paths);
        let mut members = Vec::with_capacity(request.item_ids.len());
        for (ordinal, item_id) in request.item_ids.iter().enumerate() {
            let row: (String, i64) = transaction
                .query_row(
                    "SELECT attributes_json, updated_revision
                     FROM catalog_items WHERE item_id = ?1 AND active = 1",
                    [item_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(PlatformError::Conflict("outfit_item_unavailable"))?;
            let attributes: ItemAttributesV1 = serde_json::from_str(&row.0)?;
            attributes
                .validate()
                .map_err(|_| PlatformError::Corrupt("outfit_item_attributes"))?;
            let asset = pin_item_asset(&transaction, &store, item_id)?;
            members.push(OutfitMemberV1 {
                ordinal: ordinal as u8,
                item_id: *item_id,
                item_updated_revision: to_u64(row.1, "item_updated_revision")?,
                attributes,
                asset,
            });
        }

        let next_revision = outfit_revision
            .checked_add(1)
            .ok_or(PlatformError::Corrupt("outfit_revision_overflow"))?;
        let outfit_id = stable_id("outfit", &request.request_id.to_string());
        let now_ms = unix_now_ms()?;
        transaction.execute(
            "INSERT INTO outfits(
                outfit_id, request_id, name, created_outfit_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                outfit_id,
                request.request_id.to_string(),
                request.name,
                next_revision,
                now_ms
            ],
        )?;
        for member in &members {
            insert_member(&transaction, &outfit_id, member)?;
        }
        transaction.execute(
            "UPDATE revision_state SET outfit_revision = ?1 WHERE singleton = 1",
            [next_revision],
        )?;
        let outfit = OutfitV1 {
            outfit_id: parse_outfit_id(&outfit_id)?,
            name: request.name.clone(),
            members,
            created_outfit_revision: next_revision as u64,
        };
        let response = CreateManualOutfitV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            outfit,
            outfit_revision: next_revision as u64,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("outfit_response"))?;
        transaction.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.request_id.to_string(),
                CREATE_COMMAND,
                envelope_hash,
                serde_json::to_string(&response)?,
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(response)
    }

    fn list_outfits_impl(
        &self,
        request: &ListOutfitsV1Request,
    ) -> PlatformResult<ListOutfitsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("outfit_list_request"))?;
        let connection = self.connection()?;
        let outfit_revision: i64 = connection.query_row(
            "SELECT outfit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let offset = parse_cursor(request.cursor.as_ref(), outfit_revision as u64)?;
        let total_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM outfits", [], |row| row.get(0))?;
        let mut statement = connection.prepare(
            "SELECT outfit_id FROM outfits
             ORDER BY created_outfit_revision DESC, outfit_id
             LIMIT ?1 OFFSET ?2",
        )?;
        let ids = statement
            .query_map(params![i64::from(request.limit), offset as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let outfits = ids
            .iter()
            .map(|id| load_outfit(&connection, id))
            .collect::<PlatformResult<Vec<_>>>()?;
        let next_offset = offset + outfits.len() as u64;
        let next_cursor = if next_offset < total_count as u64 {
            Some(make_cursor(outfit_revision as u64, next_offset)?)
        } else {
            None
        };
        let response = ListOutfitsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            outfits,
            total_count: total_count as u64,
            outfit_revision: outfit_revision as u64,
            next_cursor,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("outfit_list_response"))?;
        Ok(response)
    }

    fn get_outfit_collage_impl(
        &self,
        request: &GetOutfitCollageV1Request,
    ) -> PlatformResult<GetOutfitCollageV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("outfit_collage_request"))?;
        let connection = self.connection()?;
        let outfit = load_outfit(&connection, &request.outfit_id.to_string())?;
        let outfit_revision: i64 = connection.query_row(
            "SELECT outfit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let store = BlobStore::new(&self.paths);
        let members = outfit
            .members
            .into_iter()
            .map(|mut member| {
                let bytes = if member.asset.state == OutfitAssetStateV1::Available {
                    let verified = verify_pinned_asset(&store, &member.asset);
                    match verified {
                        Ok(bytes) => Some(bytes),
                        Err(_) => {
                            member.asset.state = OutfitAssetStateV1::Unavailable;
                            None
                        }
                    }
                } else {
                    None
                };
                Ok(OutfitCollageMemberV1 { member, bytes })
            })
            .collect::<PlatformResult<Vec<_>>>()?;
        let response = GetOutfitCollageV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            outfit_id: outfit.outfit_id,
            name: outfit.name,
            members,
            outfit_revision: outfit_revision as u64,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("outfit_collage_response"))?;
        Ok(response)
    }
}

fn pin_item_asset(
    transaction: &Transaction<'_>,
    store: &BlobStore,
    item_id: &ItemId,
) -> PlatformResult<OutfitAssetBindingV1> {
    let row = transaction
        .query_row(
            "SELECT e.evidence_id, e.source_id, s.blob_sha256, s.byte_length
             FROM item_evidence ie
             JOIN evidence e ON e.evidence_id = ie.evidence_id
             JOIN local_sources s ON s.source_id = e.source_id
             WHERE ie.item_id = ?1
               AND e.evidence_kind = 'image'
               AND e.state = 'assigned'
               AND s.status = 'imported'
               AND s.blob_sha256 IS NOT NULL
               AND s.byte_length IS NOT NULL
             ORDER BY e.evidence_id
             LIMIT 1",
            [item_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((evidence_id, source_id, blob_sha256, byte_length)) = row else {
        return Ok(metadata_only_asset());
    };
    let image = verify_source_image(
        store,
        &blob_sha256,
        to_u64(byte_length, "outfit_asset_length")?,
    )
    .map_err(|_| PlatformError::Corrupt("outfit_asset_verification"))?;
    Ok(OutfitAssetBindingV1 {
        state: OutfitAssetStateV1::Available,
        evidence_id: Some(parse_evidence_id(&evidence_id)?),
        source_id: Some(parse_source_id(&source_id)?),
        blob_sha256: Some(parse_digest(&blob_sha256)?),
        media_type: Some(media_type(&image.media_type).to_owned()),
        byte_length: Some(byte_length as u64),
        width: Some(image.width),
        height: Some(image.height),
    })
}

fn verify_pinned_asset(
    store: &BlobStore,
    asset: &OutfitAssetBindingV1,
) -> PlatformResult<BoundedPhotoArtifactBytesV1> {
    let digest = asset
        .blob_sha256
        .as_ref()
        .ok_or(PlatformError::Corrupt("outfit_asset_binding"))?;
    let expected_length = asset
        .byte_length
        .ok_or(PlatformError::Corrupt("outfit_asset_binding"))?;
    let image = verify_source_image(store, digest.as_str(), expected_length)
        .map_err(|_| PlatformError::Corrupt("outfit_asset_unavailable"))?;
    if Some(media_type(&image.media_type)) != asset.media_type.as_deref()
        || Some(image.width) != asset.width
        || Some(image.height) != asset.height
    {
        return Err(PlatformError::Corrupt("outfit_asset_changed"));
    }
    BoundedPhotoArtifactBytesV1::new(image.bytes)
        .map_err(|_| PlatformError::Corrupt("outfit_asset_bytes"))
}

fn insert_member(
    transaction: &Transaction<'_>,
    outfit_id: &str,
    member: &OutfitMemberV1,
) -> PlatformResult<()> {
    let state = match member.asset.state {
        OutfitAssetStateV1::Available => "available",
        OutfitAssetStateV1::MetadataOnly => "metadata_only",
        OutfitAssetStateV1::Unavailable => {
            return Err(PlatformError::InvalidInput("outfit_asset_state"))
        }
    };
    transaction.execute(
        "INSERT INTO outfit_members(
            outfit_id, ordinal, item_id, item_updated_revision, attributes_json,
            asset_state, evidence_id, source_id, blob_sha256, media_type,
            byte_length, width, height
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            outfit_id,
            i64::from(member.ordinal),
            member.item_id.to_string(),
            member.item_updated_revision as i64,
            serde_json::to_string(&member.attributes)?,
            state,
            member.asset.evidence_id.map(|value| value.to_string()),
            member.asset.source_id.map(|value| value.to_string()),
            member.asset.blob_sha256.as_ref().map(Sha256Digest::as_str),
            member.asset.media_type,
            member.asset.byte_length.map(|value| value as i64),
            member.asset.width.map(i64::from),
            member.asset.height.map(i64::from),
        ],
    )?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn load_outfit(connection: &rusqlite::Connection, outfit_id: &str) -> PlatformResult<OutfitV1> {
    let (name, revision): (String, i64) = connection
        .query_row(
            "SELECT name, created_outfit_revision FROM outfits WHERE outfit_id = ?1",
            [outfit_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("outfit_id"))?;
    let mut statement = connection.prepare(
        "SELECT ordinal, item_id, item_updated_revision, attributes_json,
                asset_state, evidence_id, source_id, blob_sha256, media_type,
                byte_length, width, height
         FROM outfit_members WHERE outfit_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([outfit_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        let state = match row.4.as_str() {
            "available" => OutfitAssetStateV1::Available,
            "metadata_only" => OutfitAssetStateV1::MetadataOnly,
            _ => return Err(PlatformError::Corrupt("outfit_asset_state")),
        };
        members.push(OutfitMemberV1 {
            ordinal: u8::try_from(row.0).map_err(|_| PlatformError::Corrupt("outfit_ordinal"))?,
            item_id: parse_item_id(&row.1)?,
            item_updated_revision: to_u64(row.2, "item_updated_revision")?,
            attributes: serde_json::from_str(&row.3)?,
            asset: OutfitAssetBindingV1 {
                state,
                evidence_id: row.5.as_deref().map(parse_evidence_id).transpose()?,
                source_id: row.6.as_deref().map(parse_source_id).transpose()?,
                blob_sha256: row.7.as_deref().map(parse_digest).transpose()?,
                media_type: row.8,
                byte_length: row
                    .9
                    .map(|value| to_u64(value, "outfit_asset_length"))
                    .transpose()?,
                width: row
                    .10
                    .map(|value| to_u32(value, "outfit_asset_width"))
                    .transpose()?,
                height: row
                    .11
                    .map(|value| to_u32(value, "outfit_asset_height"))
                    .transpose()?,
            },
        });
    }
    let outfit = OutfitV1 {
        outfit_id: parse_outfit_id(outfit_id)?,
        name,
        members,
        created_outfit_revision: to_u64(revision, "outfit_revision")?,
    };
    outfit
        .validate()
        .map_err(|_| PlatformError::Corrupt("outfit_contract"))?;
    Ok(outfit)
}

fn replay<T: DeserializeOwned>(
    transaction: &Transaction<'_>,
    request: &CreateManualOutfitV1Request,
    envelope_hash: &str,
) -> PlatformResult<Option<T>> {
    let row = transaction
        .query_row(
            "SELECT command_name, envelope_hash, response_json
             FROM command_receipts WHERE request_id = ?1",
            [request.request_id.to_string()],
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
        None => Ok(None),
        Some((command, stored_hash, response))
            if command == CREATE_COMMAND && stored_hash == envelope_hash =>
        {
            Ok(Some(serde_json::from_str(&response)?))
        }
        Some(_) => Err(PlatformError::Conflict("outfit_request_reused")),
    }
}

fn metadata_only_asset() -> OutfitAssetBindingV1 {
    OutfitAssetBindingV1 {
        state: OutfitAssetStateV1::MetadataOnly,
        evidence_id: None,
        source_id: None,
        blob_sha256: None,
        media_type: None,
        byte_length: None,
        width: None,
        height: None,
    }
}

fn make_cursor(revision: u64, offset: u64) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!("outfits:{revision}:{offset}"))
        .map_err(|_| PlatformError::Corrupt("outfit_cursor"))
}

fn parse_cursor(cursor: Option<&PageCursorV1>, revision: u64) -> PlatformResult<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let mut values = cursor.as_str().split(':');
    let kind = values.next();
    let cursor_revision = values.next().and_then(|value| value.parse::<u64>().ok());
    let offset = values.next().and_then(|value| value.parse::<u64>().ok());
    if kind != Some("outfits")
        || cursor_revision != Some(revision)
        || values.next().is_some()
        || offset.is_none()
    {
        return Err(PlatformError::Conflict("outfit_snapshot_expired"));
    }
    Ok(offset.unwrap_or_default())
}

fn hash_json<T: Serialize>(value: &T) -> PlatformResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn media_type(value: &wardrobe_core::PhotoMediaTypeV1) -> &'static str {
    match value {
        wardrobe_core::PhotoMediaTypeV1::ImageJpeg => "image/jpeg",
        wardrobe_core::PhotoMediaTypeV1::ImagePng => "image/png",
        wardrobe_core::PhotoMediaTypeV1::ImageWebp => "image/webp",
    }
}

fn parse_outfit_id(value: &str) -> PlatformResult<OutfitId> {
    OutfitId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("outfit_id"))?)
        .map_err(|_| PlatformError::Corrupt("outfit_id"))
}

fn parse_item_id(value: &str) -> PlatformResult<ItemId> {
    ItemId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("item_id"))?)
        .map_err(|_| PlatformError::Corrupt("item_id"))
}

fn parse_evidence_id(value: &str) -> PlatformResult<EvidenceId> {
    EvidenceId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("evidence_id"))?)
        .map_err(|_| PlatformError::Corrupt("evidence_id"))
}

fn parse_source_id(value: &str) -> PlatformResult<SourceId> {
    SourceId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("source_id"))?)
        .map_err(|_| PlatformError::Corrupt("source_id"))
}

fn parse_digest(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| PlatformError::Corrupt("blob_sha256"))
}

fn to_u64(value: i64, field: &'static str) -> PlatformResult<u64> {
    u64::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn to_u32(value: i64, field: &'static str) -> PlatformResult<u32> {
    u32::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn outfit_port_error(error: PlatformError) -> OutfitPortError {
    let kind = match error {
        PlatformError::Conflict("outfit_snapshot_expired") => OutfitPortErrorKind::SnapshotExpired,
        PlatformError::Conflict(_) => OutfitPortErrorKind::Conflict,
        PlatformError::InvalidInput("outfit_id") => OutfitPortErrorKind::NotFound,
        PlatformError::InvalidInput(_) | PlatformError::Unsupported(_) => {
            OutfitPortErrorKind::InvalidState
        }
        PlatformError::Corrupt(_) => OutfitPortErrorKind::DataIntegrity,
        PlatformError::Io(_) | PlatformError::Sqlite(_) => OutfitPortErrorKind::Unavailable,
        PlatformError::Json(_) | PlatformError::Keychain(_) | PlatformError::LeaseLost => {
            OutfitPortErrorKind::Internal
        }
    };
    OutfitPortError::new(kind)
}

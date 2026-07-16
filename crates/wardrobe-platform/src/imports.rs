use crate::database::stable_id;
use crate::{BlobRecord, BlobStore, Database, PlatformError, PlatformResult};
use image::codecs::png::PngDecoder;
use image::codecs::webp::WebPDecoder;
use image::{ImageFormat, ImageReader, Limits};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Cursor};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wardrobe_core::{
    ImportLocalSourcesV1Request, ImportLocalSourcesV1Response, ImportRootId, ImportSummaryV1,
    RefreshImportRootsV1Request, RefreshImportRootsV1Response, ReplayStatusV1, SourceId,
    SCHEMA_VERSION_V1,
};

const IMAGE_LIMIT: u64 = 40 * 1024 * 1024;
const EML_LIMIT: u64 = 25 * 1024 * 1024;
const MBOX_LIMIT: u64 = 256 * 1024 * 1024;
const BATCH_LIMIT: u64 = 512 * 1024 * 1024;
const FILE_LIMIT: usize = 500;
const DEPTH_LIMIT: usize = 16;
const MBOX_MESSAGE_LIMIT: usize = 2_000;
const MIME_PART_LIMIT: usize = 200;
const MIME_DEPTH_LIMIT: usize = 16;
const HEADER_LIMIT: usize = 256 * 1024;
const DECODED_PART_LIMIT: usize = 25 * 1024 * 1024;
const DECODED_TOTAL_LIMIT: usize = 100 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
struct ImportCounts {
    imported: u32,
    reused: u32,
    quarantined: u32,
    skipped: u32,
    unavailable: u32,
}

impl ImportCounts {
    fn summary(
        self,
        root_id: Option<ImportRootId>,
        source_id: Option<SourceId>,
    ) -> ImportSummaryV1 {
        ImportSummaryV1 {
            import_root_id: root_id,
            source_id,
            imported: self.imported,
            reused: self.reused,
            quarantined: self.quarantined,
            skipped: self.skipped,
            unavailable: self.unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateKind {
    Image,
    Eml,
    Mbox,
}

impl CandidateKind {
    fn limit(self) -> u64 {
        match self {
            Self::Image => IMAGE_LIMIT,
            Self::Eml => EML_LIMIT,
            Self::Mbox => MBOX_LIMIT,
        }
    }

    fn source_kind(self, in_folder: bool) -> &'static str {
        match self {
            Self::Image if in_folder => "folder_image",
            Self::Image => "folder_image",
            Self::Eml => "eml",
            Self::Mbox => "mbox",
        }
    }
}

#[derive(Debug)]
struct Candidate {
    path: PathBuf,
    metadata: fs::Metadata,
    kind: CandidateKind,
}

#[derive(Debug)]
struct Materialized {
    record: BlobRecord,
    bytes: Vec<u8>,
}

impl Database {
    pub(crate) fn import_local(
        &self,
        request: &ImportLocalSourcesV1Request,
    ) -> PlatformResult<ImportLocalSourcesV1Response> {
        if let Some(mut response) = self.replay_response::<_, ImportLocalSourcesV1Response>(
            &request.request_id.to_string(),
            "import_local_sources_v1",
            request,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }

        let now_ms = unix_now_ms()?;
        let mut summaries = Vec::with_capacity(request.paths.len());
        let mut batch_bytes = 0_u64;
        let mut changed = false;
        for (index, raw_path) in request.paths.iter().enumerate() {
            let path = Path::new(raw_path);
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    summaries.push(
                        ImportCounts {
                            unavailable: 1,
                            ..ImportCounts::default()
                        }
                        .summary(None, None),
                    );
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                let source_id = self.record_metadata_quarantine(
                    &request.request_id.to_string(),
                    index,
                    path,
                    &metadata,
                    "not_regular",
                    now_ms,
                )?;
                summaries.push(
                    ImportCounts {
                        quarantined: 1,
                        ..ImportCounts::default()
                    }
                    .summary(None, Some(parse_source_id(&source_id)?)),
                );
                changed = true;
            } else if metadata.is_dir() {
                let (summary, root_changed) = self.import_folder(
                    &request.request_id.to_string(),
                    path,
                    &metadata,
                    &mut batch_bytes,
                    now_ms,
                )?;
                summaries.push(summary);
                changed |= root_changed;
            } else {
                let kind = classify(path).ok_or(PlatformError::Unsupported("import_file_type"))?;
                let (counts, source_id, source_changed) = self.import_candidate(
                    &request.request_id.to_string(),
                    index,
                    Candidate {
                        path: path.to_path_buf(),
                        metadata,
                        kind,
                    },
                    None,
                    None,
                    &mut batch_bytes,
                    now_ms,
                )?;
                summaries.push(counts.summary(None, Some(parse_source_id(&source_id)?)));
                changed |= source_changed;
            }
        }
        let evidence_generation = self.bump_or_read_evidence_generation(changed)?;
        let response = ImportLocalSourcesV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            summaries,
            evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        self.store_response(
            &request.request_id.to_string(),
            "import_local_sources_v1",
            request,
            &response,
            now_ms,
        )?;
        Ok(response)
    }

    pub(crate) fn refresh_roots(
        &self,
        request: &RefreshImportRootsV1Request,
    ) -> PlatformResult<RefreshImportRootsV1Response> {
        if let Some(mut response) = self.replay_response::<_, RefreshImportRootsV1Response>(
            &request.request_id.to_string(),
            "refresh_import_roots_v1",
            request,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }
        let now_ms = unix_now_ms()?;
        let mut summaries = Vec::with_capacity(request.import_root_ids.len());
        let mut batch_bytes = 0_u64;
        let mut changed = false;
        for root_id in &request.import_root_ids {
            let row = self
                .connection()?
                .query_row(
                    "SELECT canonical_path, device_id, file_id FROM import_roots WHERE root_id = ?1",
                    [root_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((path, device_id, file_id)) = row else {
                return Err(PlatformError::InvalidInput("import_root_id"));
            };
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.dev() as i64 == device_id
                        && metadata.ino() as i64 == file_id =>
                {
                    metadata
                }
                _ => {
                    self.connection()?.execute(
                        "UPDATE import_roots SET status = 'unavailable', updated_at_ms = ?2
                         WHERE root_id = ?1",
                        params![root_id.to_string(), now_ms],
                    )?;
                    summaries.push(
                        ImportCounts {
                            unavailable: 1,
                            ..ImportCounts::default()
                        }
                        .summary(Some(*root_id), None),
                    );
                    continue;
                }
            };
            let (summary, root_changed) = self.import_folder(
                &request.request_id.to_string(),
                Path::new(&path),
                &metadata,
                &mut batch_bytes,
                now_ms,
            )?;
            summaries.push(summary);
            changed |= root_changed;
        }
        let evidence_generation = self.bump_or_read_evidence_generation(changed)?;
        let response = RefreshImportRootsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            summaries,
            evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        self.store_response(
            &request.request_id.to_string(),
            "refresh_import_roots_v1",
            request,
            &response,
            now_ms,
        )?;
        Ok(response)
    }

    fn import_folder(
        &self,
        request_id: &str,
        path: &Path,
        root_metadata: &fs::Metadata,
        batch_bytes: &mut u64,
        now_ms: i64,
    ) -> PlatformResult<(ImportSummaryV1, bool)> {
        let canonical = fs::canonicalize(path)?;
        let root_id_text = stable_id(
            "import-root",
            &format!("{}:{}", root_metadata.dev(), root_metadata.ino()),
        );
        let root_id = parse_import_root_id(&root_id_text)?;
        let existing_generation = self
            .connection()?
            .query_row(
                "SELECT manifest_generation FROM import_roots WHERE root_id = ?1",
                [&root_id_text],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        let generation = existing_generation + 1;
        let scan_id = stable_id(
            "import-scan",
            &format!("{request_id}:{root_id_text}:{generation}"),
        );

        let candidates = match scan_folder(&canonical) {
            Ok(candidates) => candidates,
            Err(_) => {
                if existing_generation > 0 {
                    self.connection()?.execute(
                        "UPDATE import_roots SET status = 'incomplete', updated_at_ms = ?2
                         WHERE root_id = ?1",
                        params![root_id_text, now_ms],
                    )?;
                }
                return Ok((
                    ImportCounts {
                        unavailable: 1,
                        ..ImportCounts::default()
                    }
                    .summary(Some(root_id), None),
                    false,
                ));
            }
        };

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO import_roots(
                root_id, canonical_path, device_id, file_id, status,
                manifest_generation, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, 'incomplete', ?5, ?6, ?6)
             ON CONFLICT(root_id) DO UPDATE SET canonical_path = excluded.canonical_path,
                status = 'incomplete', updated_at_ms = excluded.updated_at_ms",
            params![
                root_id_text,
                canonical.to_string_lossy(),
                root_metadata.dev() as i64,
                root_metadata.ino() as i64,
                existing_generation,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO import_scans(
                scan_id, root_id, generation, status, started_at_ms
             ) VALUES (?1, ?2, ?3, 'running', ?4)",
            params![scan_id, root_id_text, generation, now_ms],
        )?;
        transaction.commit()?;

        let mut counts = ImportCounts::default();
        let mut changed = false;
        for (index, candidate) in candidates.into_iter().enumerate() {
            let (next, _, candidate_changed) = self.import_candidate(
                request_id,
                index,
                candidate,
                Some((&root_id_text, generation)),
                Some(&canonical),
                batch_bytes,
                now_ms,
            )?;
            counts.imported += next.imported;
            counts.reused += next.reused;
            counts.quarantined += next.quarantined;
            counts.skipped += next.skipped;
            counts.unavailable += next.unavailable;
            changed |= candidate_changed;
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE local_sources SET status = 'missing', updated_at_ms = ?3
             WHERE root_id = ?1 AND manifest_generation < ?2 AND status <> 'missing'",
            params![root_id_text, generation, now_ms],
        )?;
        transaction.execute(
            "UPDATE import_roots SET status = 'available', manifest_generation = ?2,
                    updated_at_ms = ?3 WHERE root_id = ?1",
            params![root_id_text, generation, now_ms],
        )?;
        transaction.execute(
            "UPDATE import_scans SET status = 'completed', imported_count = ?2,
                    reused_count = ?3, quarantined_count = ?4, skipped_count = ?5,
                    completed_at_ms = ?6 WHERE scan_id = ?1",
            params![
                scan_id,
                counts.imported,
                counts.reused,
                counts.quarantined,
                counts.skipped,
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok((counts.summary(Some(root_id), None), changed))
    }

    #[allow(clippy::too_many_arguments)]
    fn import_candidate(
        &self,
        request_id: &str,
        index: usize,
        candidate: Candidate,
        root: Option<(&str, i64)>,
        root_path: Option<&Path>,
        batch_bytes: &mut u64,
        now_ms: i64,
    ) -> PlatformResult<(ImportCounts, String, bool)> {
        let root_identity = root.map(|(root_id, _)| root_id);
        let identity_key = match root_identity {
            Some(root_id) => format!(
                "{root_id}:{}:{}",
                candidate.metadata.dev(),
                candidate.metadata.ino()
            ),
            None => format!("{request_id}:{index}"),
        };
        let source_id = stable_id(candidate.kind.source_kind(root.is_some()), &identity_key);
        if candidate.metadata.file_type().is_symlink() || !candidate.metadata.is_file() {
            self.upsert_quarantine_source(
                &source_id,
                candidate.kind.source_kind(root.is_some()),
                &identity_key,
                &candidate.path,
                &candidate.metadata,
                root,
                "not_regular",
                None,
                now_ms,
            )?;
            return Ok((
                ImportCounts {
                    quarantined: 1,
                    ..ImportCounts::default()
                },
                source_id,
                true,
            ));
        }

        let length = candidate.metadata.len();
        let no_blob_reason = if length > candidate.kind.limit() {
            Some("size_limit")
        } else if batch_bytes.saturating_add(length) > BATCH_LIMIT {
            Some("batch_size_limit")
        } else {
            None
        };
        if let Some(reason) = no_blob_reason {
            self.upsert_quarantine_source(
                &source_id,
                candidate.kind.source_kind(root.is_some()),
                &identity_key,
                &candidate.path,
                &candidate.metadata,
                root,
                reason,
                None,
                now_ms,
            )?;
            return Ok((
                ImportCounts {
                    quarantined: 1,
                    ..ImportCounts::default()
                },
                source_id,
                true,
            ));
        }

        let materialized = match self.materialize(&candidate, root_path) {
            Ok(value) => value,
            Err(_) => {
                self.upsert_quarantine_source(
                    &source_id,
                    candidate.kind.source_kind(root.is_some()),
                    &identity_key,
                    &candidate.path,
                    &candidate.metadata,
                    root,
                    "open_or_identity_failed",
                    None,
                    now_ms,
                )?;
                return Ok((
                    ImportCounts {
                        quarantined: 1,
                        ..ImportCounts::default()
                    },
                    source_id,
                    true,
                ));
            }
        };
        *batch_bytes += materialized.record.byte_length;
        let parse_result = match candidate.kind {
            CandidateKind::Image => validate_image(&materialized.bytes).map(|_| Vec::new()),
            CandidateKind::Eml => prepare_message_parts(&materialized.bytes),
            CandidateKind::Mbox => Ok(Vec::new()),
        };
        let quarantine_reason = parse_result.as_ref().err().copied();
        let was_present = self
            .connection()?
            .query_row(
                "SELECT 1 FROM local_sources WHERE source_id = ?1",
                [&source_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let materialized_identity;
        let persisted_identity = if root.is_some() {
            identity_key.as_str()
        } else {
            materialized_identity = format!("{source_id}:{}", materialized.record.sha256);
            materialized_identity.as_str()
        };
        self.record_materialized_source(
            request_id,
            &source_id,
            candidate.kind.source_kind(root.is_some()),
            persisted_identity,
            &candidate.path,
            &candidate.metadata,
            root,
            &materialized.record,
            quarantine_reason,
            now_ms,
        )?;
        if let Ok(parts) = parse_result {
            if candidate.kind == CandidateKind::Image {
                self.ensure_evidence(&source_id, None, "image", now_ms)?;
            } else if candidate.kind == CandidateKind::Eml {
                self.record_message_parts(&source_id, parts, now_ms)?;
            }
        }
        let mut counts = if quarantine_reason.is_some() {
            ImportCounts {
                quarantined: 1,
                ..ImportCounts::default()
            }
        } else if was_present || materialized.record.reused {
            ImportCounts {
                reused: 1,
                ..ImportCounts::default()
            }
        } else {
            ImportCounts {
                imported: 1,
                ..ImportCounts::default()
            }
        };
        if candidate.kind == CandidateKind::Mbox && quarantine_reason.is_none() {
            let child_counts =
                self.import_mbox_children(request_id, &source_id, &materialized.bytes, now_ms)?;
            counts.imported += child_counts.imported;
            counts.reused += child_counts.reused;
            counts.quarantined += child_counts.quarantined;
        }
        Ok((counts, source_id, true))
    }

    fn materialize(
        &self,
        candidate: &Candidate,
        root: Option<&Path>,
    ) -> PlatformResult<Materialized> {
        if let Some(root) = root {
            let canonical_parent = fs::canonicalize(
                candidate
                    .path
                    .parent()
                    .ok_or(PlatformError::InvalidInput("import_path"))?,
            )?;
            if !canonical_parent.starts_with(root) {
                return Err(PlatformError::InvalidInput("import_traversal"));
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&candidate.path)?;
        let opened = file.metadata()?;
        if !opened.is_file()
            || opened.dev() != candidate.metadata.dev()
            || opened.ino() != candidate.metadata.ino()
            || opened.len() != candidate.metadata.len()
        {
            return Err(PlatformError::Conflict("import_file_changed"));
        }
        let store = BlobStore::new(&self.paths);
        let record = store.put_reader(&mut file, opened.len(), candidate.kind.limit())?;
        let after = file.metadata()?;
        if after.dev() != opened.dev() || after.ino() != opened.ino() || after.len() != opened.len()
        {
            return Err(PlatformError::Conflict("import_file_changed"));
        }
        let bytes = fs::read(&record.path)?;
        if bytes.len() as u64 != record.byte_length {
            return Err(PlatformError::Corrupt("import_blob_length"));
        }
        Ok(Materialized { record, bytes })
    }

    fn import_mbox_children(
        &self,
        request_id: &str,
        parent_source_id: &str,
        bytes: &[u8],
        now_ms: i64,
    ) -> PlatformResult<ImportCounts> {
        let slices = split_mboxrd(bytes)?;
        let mut occurrences: BTreeMap<String, u32> = BTreeMap::new();
        let mut counts = ImportCounts::default();
        for (start, end) in slices {
            let raw = &bytes[start..end];
            let hash = format!("{:x}", Sha256::digest(raw));
            let ordinal = occurrences.entry(hash.clone()).or_default();
            let identity = format!("{parent_source_id}:{hash}:{ordinal}");
            let source_id = stable_id("mbox-message", &identity);
            let existed = self
                .connection()?
                .query_row(
                    "SELECT 1 FROM local_sources WHERE source_id = ?1",
                    [&source_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let blob = BlobStore::new(&self.paths).put(raw, Some(&hash), EML_LIMIT)?;
            self.record_mbox_child(
                request_id,
                parent_source_id,
                &source_id,
                &identity,
                &blob,
                start,
                end,
                *ordinal,
                now_ms,
            )?;
            *ordinal += 1;
            let parser_input = unescape_mboxrd(raw);
            match prepare_message_parts(&parser_input) {
                Ok(parts) => {
                    self.record_message_parts(&source_id, parts, now_ms)?;
                    if existed || blob.reused {
                        counts.reused += 1;
                    } else {
                        counts.imported += 1;
                    }
                }
                Err(reason) => {
                    self.mark_source_quarantined(&source_id, reason, true, now_ms)?;
                    counts.quarantined += 1;
                }
            }
        }
        Ok(counts)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_materialized_source(
        &self,
        request_id: &str,
        source_id: &str,
        source_kind: &str,
        identity_key: &str,
        path: &Path,
        metadata: &fs::Metadata,
        root: Option<(&str, i64)>,
        blob: &BlobRecord,
        quarantine_reason: Option<&str>,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_blob_record(&transaction, blob, now_ms)?;
        transaction.execute(
            "INSERT INTO local_sources(
                source_id, root_id, source_kind, identity_key, canonical_locator,
                device_id, file_id, raw_sha256, blob_sha256, byte_length, media_type,
                status, no_blob_reason, manifest_generation, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?13)
             ON CONFLICT(source_kind, identity_key) DO UPDATE SET
                canonical_locator = excluded.canonical_locator,
                raw_sha256 = excluded.raw_sha256, blob_sha256 = excluded.blob_sha256,
                byte_length = excluded.byte_length, media_type = excluded.media_type,
                status = excluded.status, no_blob_reason = NULL,
                manifest_generation = excluded.manifest_generation,
                updated_at_ms = excluded.updated_at_ms",
            params![
                source_id,
                root.map(|value| value.0),
                source_kind,
                identity_key,
                bounded_locator(path),
                metadata.dev() as i64,
                metadata.ino() as i64,
                blob.sha256,
                blob.byte_length as i64,
                source_kind,
                if quarantine_reason.is_some() {
                    "quarantined"
                } else {
                    "imported"
                },
                root.map(|value| value.1),
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO source_provenance(
                provenance_id, source_id, request_id, observed_locator,
                raw_sha256, blob_sha256, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params![
                stable_id("source-provenance", &format!("{source_id}:{request_id}")),
                source_id,
                request_id,
                bounded_locator(path),
                blob.sha256,
                now_ms
            ],
        )?;
        if let Some(reason) = quarantine_reason {
            insert_quarantine(&transaction, source_id, reason, now_ms)?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_quarantine_source(
        &self,
        source_id: &str,
        source_kind: &str,
        identity_key: &str,
        path: &Path,
        metadata: &fs::Metadata,
        root: Option<(&str, i64)>,
        reason: &str,
        blob: Option<&BlobRecord>,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(record) = blob {
            insert_blob_record(&transaction, record, now_ms)?;
        }
        transaction.execute(
            "INSERT INTO local_sources(
                source_id, root_id, source_kind, identity_key, canonical_locator,
                device_id, file_id, raw_sha256, blob_sha256, byte_length, media_type,
                status, no_blob_reason, manifest_generation, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?3,
                       'quarantined', ?10, ?11, ?12, ?12)
             ON CONFLICT(source_kind, identity_key) DO UPDATE SET
                canonical_locator = excluded.canonical_locator,
                status = 'quarantined', no_blob_reason = excluded.no_blob_reason,
                manifest_generation = excluded.manifest_generation,
                updated_at_ms = excluded.updated_at_ms",
            params![
                source_id,
                root.map(|value| value.0),
                source_kind,
                identity_key,
                bounded_locator(path),
                metadata.dev() as i64,
                metadata.ino() as i64,
                blob.map(|value| value.sha256.as_str()),
                blob.map(|value| value.byte_length as i64),
                if blob.is_some() {
                    None::<&str>
                } else {
                    Some(reason)
                },
                root.map(|value| value.1),
                now_ms
            ],
        )?;
        insert_quarantine(&transaction, source_id, reason, now_ms)?;
        transaction.commit()?;
        Ok(())
    }

    fn record_metadata_quarantine(
        &self,
        request_id: &str,
        index: usize,
        path: &Path,
        metadata: &fs::Metadata,
        reason: &str,
        now_ms: i64,
    ) -> PlatformResult<String> {
        let identity = format!("{request_id}:{index}:{}:{}", metadata.dev(), metadata.ino());
        let source_id = stable_id("quarantined-file", &identity);
        self.upsert_quarantine_source(
            &source_id,
            "folder_image",
            &identity,
            path,
            metadata,
            None,
            reason,
            None,
            now_ms,
        )?;
        Ok(source_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_mbox_child(
        &self,
        request_id: &str,
        parent_source_id: &str,
        source_id: &str,
        identity: &str,
        blob: &BlobRecord,
        start: usize,
        end: usize,
        ordinal: u32,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_blob_record(&transaction, blob, now_ms)?;
        transaction.execute(
            "INSERT INTO local_sources(
                source_id, parent_source_id, source_kind, identity_key, canonical_locator,
                raw_sha256, blob_sha256, byte_length, byte_start, byte_end,
                occurrence_ordinal, media_type, status, no_blob_reason, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, 'mbox_message', ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9,
                       'message/rfc822', 'imported', NULL, ?10, ?10)
             ON CONFLICT(source_kind, identity_key) DO UPDATE SET
                byte_start = excluded.byte_start, byte_end = excluded.byte_end,
                updated_at_ms = excluded.updated_at_ms",
            params![
                source_id,
                parent_source_id,
                identity,
                format!("mbox:{parent_source_id}:{ordinal}"),
                blob.sha256,
                blob.byte_length as i64,
                start as i64,
                end as i64,
                ordinal,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO source_provenance(
                provenance_id, source_id, request_id, observed_locator,
                raw_sha256, blob_sha256, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params![
                stable_id("source-provenance", &format!("{source_id}:{request_id}")),
                source_id,
                request_id,
                format!("mbox:{parent_source_id}:{ordinal}"),
                blob.sha256,
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn record_message_parts(
        &self,
        source_id: &str,
        parts: Vec<PreparedMimePart>,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for part in parts {
            let part_id = stable_id("mime-part", &format!("{source_id}:{}", part.ordinal));
            let parent_part_id = part
                .parent_ordinal
                .map(|ordinal| stable_id("mime-part", &format!("{source_id}:{ordinal}")));
            transaction.execute(
                "INSERT OR IGNORE INTO mime_parts(
                    part_id, source_id, parent_part_id, ordinal, content_type,
                    content_disposition, content_id, body_kind, decoded_bytes
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    part_id,
                    source_id,
                    parent_part_id,
                    part.ordinal as i64,
                    part.content_type,
                    part.disposition,
                    part.content_id,
                    part.body_kind,
                    part.decoded_bytes as i64
                ],
            )?;
            if part.is_image {
                ensure_evidence_tx(
                    &transaction,
                    source_id,
                    Some(&part_id),
                    "message_attachment",
                    now_ms,
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn ensure_evidence(
        &self,
        source_id: &str,
        part_id: Option<&str>,
        kind: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let connection = self.connection()?;
        ensure_evidence_tx(&connection, source_id, part_id, kind, now_ms)?;
        Ok(())
    }

    fn mark_source_quarantined(
        &self,
        source_id: &str,
        reason: &str,
        raw_preserved: bool,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE local_sources SET status = 'quarantined',
                    no_blob_reason = CASE WHEN ?2 THEN NULL ELSE ?3 END,
                    updated_at_ms = ?4 WHERE source_id = ?1",
            params![source_id, raw_preserved, reason, now_ms],
        )?;
        insert_quarantine(&transaction, source_id, reason, now_ms)?;
        transaction.commit()?;
        Ok(())
    }

    fn bump_or_read_evidence_generation(&self, changed: bool) -> PlatformResult<u64> {
        let connection = self.connection()?;
        if changed {
            connection.execute(
                "UPDATE revision_state SET evidence_generation = evidence_generation + 1
                 WHERE singleton = 1",
                [],
            )?;
        }
        let value: i64 = connection.query_row(
            "SELECT evidence_generation FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(value).map_err(|_| PlatformError::Corrupt("evidence_generation"))
    }

    fn replay_response<Q: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        request_id: &str,
        command: &str,
        request: &Q,
    ) -> PlatformResult<Option<T>> {
        let row = self
            .connection()?
            .query_row(
                "SELECT command_name, envelope_hash, response_json
                 FROM command_receipts WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let expected = format!("{:x}", Sha256::digest(serde_json::to_vec(request)?));
        match row {
            Some((stored_command, envelope, json))
                if stored_command == command && envelope == expected =>
            {
                Ok(Some(serde_json::from_str(&json)?))
            }
            Some(_) => Err(PlatformError::Conflict("command_envelope_changed")),
            None => Ok(None),
        }
    }

    fn store_response<Q: serde::Serialize, R: serde::Serialize>(
        &self,
        request_id: &str,
        command: &str,
        request: &Q,
        response: &R,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let envelope = format!("{:x}", Sha256::digest(serde_json::to_vec(request)?));
        self.connection()?.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request_id,
                command,
                envelope,
                serde_json::to_string(response)?,
                now_ms
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct PreparedMimePart {
    pub(crate) ordinal: usize,
    pub(crate) parent_ordinal: Option<usize>,
    pub(crate) content_type: String,
    pub(crate) disposition: Option<String>,
    pub(crate) content_id: Option<String>,
    pub(crate) body_kind: &'static str,
    pub(crate) decoded_bytes: usize,
    pub(crate) is_image: bool,
}

fn scan_folder(root: &Path) -> PlatformResult<Vec<Candidate>> {
    let mut queue = VecDeque::from([(root.to_path_buf(), 0_usize)]);
    let mut candidates = Vec::new();
    let mut seen = 0_usize;
    while let Some((directory, depth)) = queue.pop_front() {
        if depth > DEPTH_LIMIT {
            return Err(PlatformError::InvalidInput("import_depth_limit"));
        }
        let mut entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            seen += 1;
            if seen > FILE_LIMIT {
                return Err(PlatformError::InvalidInput("import_file_limit"));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                if let Some(kind) = classify(&path) {
                    candidates.push(Candidate {
                        path,
                        metadata,
                        kind,
                    });
                }
                continue;
            }
            if metadata.is_dir() {
                queue.push_back((path, depth + 1));
            } else if metadata.is_file() {
                if let Some(kind) = classify(&path) {
                    candidates.push(Candidate {
                        path,
                        metadata,
                        kind,
                    });
                }
            }
        }
    }
    Ok(candidates)
}

fn classify(path: &Path) -> Option<CandidateKind> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "webp" => Some(CandidateKind::Image),
        "eml" => Some(CandidateKind::Eml),
        "mbox" => Some(CandidateKind::Mbox),
        _ => None,
    }
}

fn validate_image(bytes: &[u8]) -> Result<(), &'static str> {
    let format = image::guess_format(bytes).map_err(|_| "image_magic_invalid")?;
    if !matches!(
        format,
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP
    ) {
        return Err("image_format_unsupported");
    }
    match format {
        ImageFormat::Png => {
            let decoder = PngDecoder::new(Cursor::new(bytes)).map_err(|_| "image_decode_failed")?;
            if decoder.is_apng().map_err(|_| "image_decode_failed")? {
                return Err("image_animated");
            }
        }
        ImageFormat::WebP => {
            let decoder =
                WebPDecoder::new(Cursor::new(bytes)).map_err(|_| "image_decode_failed")?;
            if decoder.has_animation() {
                return Err("image_animated");
            }
        }
        _ => {}
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    let mut reader = ImageReader::with_format(BufReader::new(Cursor::new(bytes)), format);
    reader.limits(limits.clone());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| "image_decode_failed")?;
    if u64::from(width).saturating_mul(u64::from(height)) > 64 * 1024 * 1024 {
        return Err("image_pixel_limit");
    }
    let mut reader = ImageReader::with_format(BufReader::new(Cursor::new(bytes)), format);
    reader.limits(limits);
    reader.decode().map_err(|_| "image_decode_failed")?;
    Ok(())
}

pub(crate) fn prepare_message_parts(bytes: &[u8]) -> Result<Vec<PreparedMimePart>, &'static str> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|offset| offset + 2)
        })
        .ok_or("mail_headers_invalid")?;
    if header_end > HEADER_LIMIT {
        return Err("mail_header_limit");
    }
    let message = MessageParser::default()
        .parse(bytes)
        .ok_or("mail_parse_failed")?;
    if message.parts.len() > MIME_PART_LIMIT {
        return Err("mail_part_limit");
    }
    let aggregate_headers = message.parts.iter().try_fold(0_usize, |total, part| {
        let header_bytes = part
            .offset_body
            .checked_sub(part.offset_header)
            .ok_or("mail_headers_invalid")? as usize;
        total.checked_add(header_bytes).ok_or("mail_header_limit")
    })?;
    if aggregate_headers > HEADER_LIMIT {
        return Err("mail_header_limit");
    }
    let mut parents = vec![None; message.parts.len()];
    for (parent, part) in message.parts.iter().enumerate() {
        if let PartType::Multipart(children) = &part.body {
            for child in children {
                let child = *child as usize;
                if child >= parents.len() {
                    return Err("mail_parse_failed");
                }
                parents[child] = Some(parent);
            }
        }
    }
    let mut total = 0_usize;
    let mut parsed = Vec::with_capacity(message.parts.len());
    for (ordinal, part) in message.parts.iter().enumerate() {
        let (body_kind, decoded_bytes) = match &part.body {
            PartType::Text(value) => ("text", value.len()),
            PartType::Html(value) => ("html", value.len()),
            PartType::Binary(value) | PartType::InlineBinary(value) => ("binary", value.len()),
            PartType::Message(value) => ("message", value.raw_message.len()),
            PartType::Multipart(children) => {
                if children.len() > MIME_PART_LIMIT {
                    return Err("mail_part_limit");
                }
                ("multipart", 0)
            }
        };
        if decoded_bytes > DECODED_PART_LIMIT {
            return Err("mail_decoded_part_limit");
        }
        total = total
            .checked_add(decoded_bytes)
            .ok_or("mail_decoded_total_limit")?;
        if total > DECODED_TOTAL_LIMIT {
            return Err("mail_decoded_total_limit");
        }
        let content_type = part
            .content_type()
            .map(|value| {
                format!(
                    "{}/{}",
                    value.c_type,
                    value.c_subtype.as_deref().unwrap_or("octet-stream")
                )
            })
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        let disposition = part
            .content_disposition()
            .map(|value| value.c_type.to_string());
        parsed.push(PreparedMimePart {
            ordinal,
            parent_ordinal: parents[ordinal],
            is_image: content_type.starts_with("image/"),
            content_type,
            disposition,
            content_id: part.content_id().map(ToOwned::to_owned),
            body_kind,
            decoded_bytes,
        });
    }
    if mime_depth(&message.parts, 0, 0)? > MIME_DEPTH_LIMIT {
        return Err("mail_depth_limit");
    }
    Ok(parsed)
}

fn mime_depth(
    parts: &[mail_parser::MessagePart<'_>],
    part_id: usize,
    depth: usize,
) -> Result<usize, &'static str> {
    if depth > MIME_DEPTH_LIMIT || part_id >= parts.len() {
        return Err("mail_depth_limit");
    }
    match &parts[part_id].body {
        PartType::Multipart(children) => children.iter().try_fold(depth, |max_depth, child| {
            Ok(max_depth.max(mime_depth(parts, *child as usize, depth + 1)?))
        }),
        _ => Ok(depth),
    }
}

fn split_mboxrd(bytes: &[u8]) -> PlatformResult<Vec<(usize, usize)>> {
    let mut delimiters = Vec::new();
    let mut line_start = 0_usize;
    while line_start < bytes.len() {
        let line_end = bytes[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| line_start + offset + 1)
            .unwrap_or(bytes.len());
        if bytes[line_start..line_end].starts_with(b"From ") {
            delimiters.push((line_start, line_end));
            if delimiters.len() > MBOX_MESSAGE_LIMIT {
                return Err(PlatformError::InvalidInput("mbox_message_limit"));
            }
        }
        line_start = line_end;
    }
    if delimiters.is_empty() {
        return Err(PlatformError::InvalidInput("mbox_delimiter_missing"));
    }
    let mut slices = Vec::with_capacity(delimiters.len());
    for (index, (_, message_start)) in delimiters.iter().enumerate() {
        let end = delimiters
            .get(index + 1)
            .map(|(delimiter_start, _)| *delimiter_start)
            .unwrap_or(bytes.len());
        if *message_start < end {
            slices.push((*message_start, end));
        }
    }
    Ok(slices)
}

fn unescape_mboxrd(raw: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b">From ") {
            output.extend_from_slice(&line[1..]);
        } else {
            output.extend_from_slice(line);
        }
    }
    output
}

fn insert_blob_record(
    connection: &rusqlite::Connection,
    blob: &BlobRecord,
    now_ms: i64,
) -> PlatformResult<()> {
    connection.execute(
        "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms) VALUES (?1, ?2, ?3)",
        params![blob.sha256, blob.byte_length as i64, now_ms],
    )?;
    let length: i64 = connection.query_row(
        "SELECT byte_length FROM blobs WHERE sha256 = ?1",
        [&blob.sha256],
        |row| row.get(0),
    )?;
    if length != blob.byte_length as i64 {
        return Err(PlatformError::Conflict("blob_length_changed"));
    }
    Ok(())
}

fn insert_quarantine(
    connection: &rusqlite::Connection,
    source_id: &str,
    reason: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    connection.execute(
        "INSERT INTO quarantine_records(
            quarantine_id, source_id, reason_code, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(source_id) DO UPDATE SET reason_code = excluded.reason_code",
        params![
            stable_id("quarantine", source_id),
            source_id,
            reason,
            now_ms
        ],
    )?;
    Ok(())
}

fn ensure_evidence_tx(
    connection: &rusqlite::Connection,
    source_id: &str,
    part_id: Option<&str>,
    kind: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    let identity = format!("{source_id}:{}", part_id.unwrap_or("root"));
    connection.execute(
        "INSERT OR IGNORE INTO evidence(
            evidence_id, source_id, part_id, evidence_kind, state, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'unresolved', ?5, ?5)",
        params![
            stable_id("evidence", &identity),
            source_id,
            part_id,
            kind,
            now_ms
        ],
    )?;
    Ok(())
}

fn bounded_locator(path: &Path) -> String {
    let value = path.to_string_lossy();
    value.chars().take(4_096).collect()
}

fn parse_source_id(value: &str) -> PlatformResult<SourceId> {
    SourceId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("source_id"))?)
        .map_err(|_| PlatformError::Corrupt("source_id"))
}

fn parse_import_root_id(value: &str) -> PlatformResult<ImportRootId> {
    ImportRootId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("import_root_id"))?)
        .map_err(|_| PlatformError::Corrupt("import_root_id"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mboxrd_split_preserves_raw_and_unescapes_only_parser_input() {
        let bytes =
            b"From sender Tue\nSubject: one\n\n>From body\nFrom sender Wed\nSubject: two\n\nbody\n";
        let slices = split_mboxrd(bytes).unwrap();
        assert_eq!(slices.len(), 2);
        let first = &bytes[slices[0].0..slices[0].1];
        assert!(first.starts_with(b"Subject: one"));
        assert!(first.windows(6).any(|window| window == b">From "));
        let parser = unescape_mboxrd(first);
        assert!(parser.windows(5).any(|window| window == b"From "));
    }

    #[test]
    fn parser_accepts_real_mime_and_rejects_unbounded_headers() {
        let message = b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=a.png\r\n\r\nabc\r\n--x--\r\n";
        let parts = prepare_message_parts(message).unwrap();
        assert!(parts.iter().any(|part| part.is_image));

        let mut oversized = b"Subject: ".to_vec();
        oversized.extend(vec![b'a'; HEADER_LIMIT + 1]);
        oversized.extend_from_slice(b"\r\n\r\nbody");
        assert!(matches!(
            prepare_message_parts(&oversized),
            Err("mail_header_limit")
        ));
    }
}

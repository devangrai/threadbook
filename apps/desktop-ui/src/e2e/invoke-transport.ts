import type { InvokeCommand } from "../invoke-transport";
import type {
  CatalogItemV1,
  CorrectedReceiptOrderV1,
  DecisionKindV1,
  DeletionDependencyClassV1,
  DeletionPlanItemV1,
  EvidenceSnapshotV1,
  GmailConnectorSettingsV1,
  GmailConnectorStatusV1,
  ItemAttributesV1,
  OutfitV1,
  PhotoObservationStateV1,
  PhotoOwnerReviewStateV1,
  PhotoPersonInstanceV1,
  PhotoReviewActionV1,
  QuarantineSnapshotV1,
  ReconciliationCaseV2,
  ReconciliationOutcomeV1,
  RectV1,
  ReceiptReviewActionV1,
  ReceiptReviewDecisionV1,
  ReceiptStateV1,
} from "../generated/contracts";
import type {
  CatalogItem,
  Evidence,
  ImportRoot,
} from "../catalog-model";
import {
  parsedReceiptFixture,
  processingFixture,
  receiptIds,
  receiptOrderFixture,
  receiptSummaryFixture,
} from "../receipt-test-data";

const TEST_TRANSPORT_MARKER = "__WARDROBE_E2E_TRANSPORT__";
const pageSize = 2;
let revision = 7;
let decisionSequence = 1;
let pendingDeletionPlan: {
  itemId: string;
  token: string;
  planSha256: string;
  revisions: Record<string, number>;
} | null = null;
let deletionReceipt: {
  requestId: string;
  envelope: string;
  response: Record<string, unknown>;
} | null = null;
const outfitStorageKey = "wardrobe-e2e-outfits-v1";
const persistedOutfits = loadOutfitState();
let outfitRevision = persistedOutfits.outfitRevision;
let savedOutfits: OutfitV1[] = persistedOutfits.savedOutfits;
const tryOnStorageKey = "wardrobe-e2e-try-on-v1";
let tryOnState = loadTryOnState();
const recoveredTryOnAfterReload = tryOnState !== null;

type PersistedReceiptState = {
  analyzed: boolean;
  state: ReceiptStateV1;
  correctedOrder: CorrectedReceiptOrderV1 | null;
  receiptRevision: number;
  reviewSequence: number;
};

type PersistedOutfitState = {
  outfitRevision: number;
  savedOutfits: OutfitV1[];
};

type PersistedTryOnState = {
  approvalId: string;
  jobId: string;
  outfitId: string;
  state: "queued" | "succeeded";
};

const receiptStorageKey = "wardrobe-e2e-receipt-state-v1";
let receiptState = loadReceiptState();
const photoStorageKey = "wardrobe-e2e-photo-state-v1";
const callStorageKey = "wardrobe-e2e-invocations-v1";

type PersistedPhotoState = {
  scopeCreated: boolean;
  detected: boolean;
  analyzed: boolean;
  detectionRevision: number;
  ownerRevision: number;
  ownerConfirmed: boolean;
  manualPersonAdded: boolean;
  photoRevision: number;
  observationState: PhotoObservationStateV1;
  reviewAction: PhotoReviewActionV1 | null;
  rectangle: RectV1;
  artifactId: string;
  promptSequence: number;
};

let photoState = loadPhotoState();
const gmailStorageKey = "wardrobe-e2e-gmail-state-v1";

type PersistedGmailState = {
  settings: GmailConnectorSettingsV1 | null;
  status: GmailConnectorStatusV1;
};

let gmailState = loadGmailState();

const photoIds = {
  root: "91000000-0000-4000-8000-000000000001",
  scan: "91000000-0000-4000-8000-000000000002",
  scope: "91000000-0000-4000-8000-000000000003",
  run: "91000000-0000-4000-8000-000000000004",
  detectionRun: "91000000-0000-4000-8000-000000000104",
  ownerReview: "91000000-0000-4000-8000-000000000105",
  failureReview: "91000000-0000-4000-8000-000000000106",
  preview: "91000000-0000-4000-8000-000000000107",
  detectionAttempt: "91000000-0000-4000-8000-000000000108",
  person: "91000000-0000-4000-8000-000000000109",
  manualPerson: "91000000-0000-4000-8000-000000000110",
  ownerDecision: "91000000-0000-4000-8000-000000000111",
  observation: "91000000-0000-4000-8000-000000000005",
  sourceRevision: "91000000-0000-4000-8000-000000000006",
  artifact: "91000000-0000-4000-8000-000000000007",
};
const photoMembershipSha256 = "1234567890abcdef".repeat(4);
const photoBytesSha256 =
  "f81609ee5b15c7d7e30fc4c6a2d8fd474c6e3d526770dd712938327d643299cc";
const photoBytes = [
  137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0,
  0, 2, 0, 0, 0, 2, 8, 2, 0, 0, 0, 253, 212, 154, 115, 0, 0, 0, 20,
  73, 68, 65, 84, 120, 218, 99, 248, 207, 192, 0, 68, 12, 12, 140, 48,
  6, 0, 44, 1, 1, 255, 133, 222, 42, 0, 0, 0, 0, 73, 69, 78, 68, 174,
  66, 96, 130,
];

const reconciliationIds = {
  case: "92000000-0000-4000-8000-000000000001",
  wardrobe: "92000000-0000-4000-8000-000000000002",
  receipt: "92000000-0000-4000-8000-000000000003",
  wardrobeAlternative: "92000000-0000-4000-8000-000000000004",
  noMatch: "92000000-0000-4000-8000-000000000005",
};
let reconciliationRevision = 30;
let reconciliationCaseRevision = 1;
let reconciliationDecisionSequence = 0;
let reconciliationDecisionHead: ReconciliationCaseV2["decision_head"] = null;
let reconciliationOpened = false;

let items: CatalogItem[] = [
  item("10000000-0000-4000-8000-000000000001", "White Oxford Shirt", "top", "White", [
    "20000000-0000-4000-8000-000000000001",
    "20000000-0000-4000-8000-000000000002",
  ]),
  item("10000000-0000-4000-8000-000000000002", "Navy Chinos", "bottom", "Navy", [
    "20000000-0000-4000-8000-000000000003",
    "20000000-0000-4000-8000-000000000004",
  ]),
  item("10000000-0000-4000-8000-000000000003", "Grey Merino Sweater", "top", "Grey", [
    "20000000-0000-4000-8000-000000000005",
  ]),
  item("10000000-0000-4000-8000-000000000004", "Black Derby Shoes", "shoes", "Black", [
    "20000000-0000-4000-8000-000000000006",
  ]),
];

let evidence: Evidence[] = [
  evidenceRow("30000000-0000-4000-8000-000000000001", "White shirt order", "email"),
  evidenceRow("30000000-0000-4000-8000-000000000002", "Dinner photo", "image"),
  evidenceRow("30000000-0000-4000-8000-000000000003", "Navy trousers order", "email"),
  evidenceRow("30000000-0000-4000-8000-000000000004", "Weekend photo", "image"),
  {
    ...evidenceRow(
      "30000000-0000-4000-8000-000000000005",
      "Unsupported animation",
      "image",
    ),
    state: "quarantine",
    quarantine_reason: "animated_image",
  },
];

const roots: ImportRoot[] = [
  {
    root_id: "40000000-0000-4000-8000-000000000001",
    display_name: "Pictures/Wardrobe",
    status: "available",
  },
];

const undoSnapshots = new Map<string, CatalogItem[]>();
const deletionRows: Record<
  DeletionDependencyClassV1,
  Array<{ id: string; label: string }>
> = {
  originals: [],
  derivatives: [],
  source_records: [],
  evidence_records: [
    { id: "d1", label: "Order confirmation" },
    { id: "d2", label: "Dinner photo" },
    { id: "d3", label: "Manual note" },
  ],
  decision_records: [
    { id: "d4", label: "Initial item decision" },
    { id: "d5", label: "Latest edit decision" },
  ],
  remote_references: [],
  retained_shared_blobs: [{ id: "d6", label: "Shared order attachment" }],
};

type Request = Record<string, unknown>;
type TestWindow = Window & {
  __WARDROBE_E2E__?: {
    marker: string;
    calls: Array<{ command: string; request: Request }>;
  };
};

function requestFrom(args?: Record<string, unknown>): Request {
  return (args?.request ?? {}) as Request;
}

function exposeCall(command: string, request: Request) {
  const target = window as TestWindow;
  target.__WARDROBE_E2E__ ??= {
    marker: TEST_TRANSPORT_MARKER,
    calls: loadPersistedCalls(),
  };
  target.__WARDROBE_E2E__.calls.push({
    command,
    request: structuredClone(request),
  });
  sessionStorage.setItem(
    callStorageKey,
    JSON.stringify(target.__WARDROBE_E2E__.calls),
  );
}

export const productionInvoke: InvokeCommand = async <T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> => {
  const request = requestFrom(args);
  exposeCall(command, request);

  switch (command) {
    case "get_foundation_snapshot_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        snapshot: {
          schema_version: 1,
          versions: {
            application: "0.1.0-e2e",
            database_schema: 2,
            job_pipeline: 1,
          },
          local_settings: {
            local_only: true,
            storage_status: "ready",
            deletion_health: {
              status: "none",
              deadline_at: null,
              counts: { in_progress: 0, overdue: 0, needs_attention: 0 },
            },
          },
          credential_references: [
            {
              credential_id: "94000000-0000-4000-8000-000000000001",
              provider: "open_ai",
              display_label: "Synthetic OpenAI",
              status: "active",
              updated_at: "2026-07-15T00:00:00Z",
            },
          ],
          recent_jobs: [],
          catalog: {
            items: items.map((value) => ({
              item_id: value.item_id,
              display_name: value.display_name,
            })),
          },
        },
      } as T;

    case "preview_outfit_recommendation_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        provider_status: "ready",
        disclosure: {
          provider: "openai",
          model: "gpt-5.6-sol",
          purpose: "outfit_recommendation",
          disclosed_field_classes: [
            "prompt",
            "explicit_constraints",
            "excluded_item_ids",
            "item_ids",
            "display_names",
            "categories",
            "primary_colors",
            "brands",
            "capability_tags",
            "wear_history",
            "style_preferences",
            "saved_outfit_membership",
          ],
          photos_disclosed: false,
          email_disclosed: false,
          paths_disclosed: false,
          notes_disclosed: false,
          sizes_disclosed: false,
          evidence_metadata_disclosed: false,
          retention: {
            revision: "openai-outfit-data-boundary-2026-07-15-v1",
            declaration: request.envelope
              ? (request.envelope as Record<string, unknown>).retention
              : { mode: "unknown", provenance: "user_not_declared" },
            store: false,
            store_false_is_not_zdr: true,
            default_abuse_monitoring_max_days: 30,
            safety_review_exceptions_apply: true,
            prompt_cache_mode: "explicit",
            prompt_cache_breakpoint_count: 0,
            prompt_cache_ttl_minimum_default: "30m",
            prompt_cache_may_retain_longer: true,
            no_breakpoints_no_cache_reads_or_writes: true,
          },
        },
        approval: {
          approval_id: "94000000-0000-4000-8000-000000000002",
          expires_at: "2026-07-15T00:10:00Z",
          single_use: true,
          catalog_revision: revision,
          outfit_revision: outfitRevision,
        },
      } as T;

    case "request_outfit_recommendation_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        outcome: {
          outcome: "completed",
          recommendation: {
            schema_revision: "outfit-recommendation-schema-v1",
            compatibility_revision: "outfit-compatibility-v1",
            capability_revision: "outfit-capability-v1",
            catalog_revision: revision,
            outfit_revision: outfitRevision,
            proposals: [
              {
                name: "Grounded dinner",
                item_ids: [items[0].item_id, items[1].item_id],
                rationale: "A simple combination from the confirmed wardrobe.",
                caveats: [],
                unresolved_constraints: [],
                constraint_assessment: [
                  {
                    constraint: "occasion",
                    status: "satisfied",
                    reason: null,
                    caveat: null,
                  },
                ],
              },
            ],
          },
          audit: {
            provider: "openai",
            model: "gpt-5.6-sol",
            provider_request_id: "req_synthetic",
            response_id: "resp_synthetic",
            retention: {
              revision: "openai-outfit-data-boundary-2026-07-15-v1",
              declaration: { mode: "unknown", provenance: "user_not_declared" },
              store: false,
              store_false_is_not_zdr: true,
              default_abuse_monitoring_max_days: 30,
              safety_review_exceptions_apply: true,
              prompt_cache_mode: "explicit",
              prompt_cache_breakpoint_count: 0,
              prompt_cache_ttl_minimum_default: "30m",
              prompt_cache_may_retain_longer: true,
              no_breakpoints_no_cache_reads_or_writes: true,
            },
            reported_cache_usage: false,
            usage: {
              input_tokens: 20,
              output_tokens: 20,
              reasoning_tokens: 5,
              response_calls: 2,
              tool_calls: 1,
              prompt_cache_read_tokens: 0,
              prompt_cache_write_tokens: 0,
            },
          },
        },
      } as T;

    case "list_try_on_portrait_candidates_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        candidates: [
          {
            source_revision_id: photoIds.sourceRevision,
            artifact_id: photoIds.artifact,
            captured_at: "2026-07-14T18:30:00Z",
            media_type: "image/png",
            width: 2,
            height: 2,
            bytes_sha256: photoBytesSha256,
            thumbnail_bytes: photoBytes,
          },
        ],
        total_count: 1,
        photo_revision: photoState.photoRevision,
        next_cursor: null,
      } as T;

    case "preview_try_on_v1": {
      const outfit = savedOutfits.find(
        (candidate) => candidate.outfit_id === request.outfit_id,
      );
      if (
        !outfit ||
        request.portrait_source_revision_id !== photoIds.sourceRevision ||
        request.expected_outfit_revision !== outfitRevision
      ) {
        throw commandError("request_conflict");
      }
      const approvalId = "95000000-0000-4000-8000-000000000001";
      return {
        schema_version: 1,
        request_id: request.request_id,
        disclosure: {
          provider: "openai",
          model: "gpt-image-2",
          purpose: "outfit_try_on_visualization",
          prompt_revision: "p08-try-on-prompt-v1",
          assets: [
            {
              ordinal: 0,
              role: "portrait",
              transmitted_filename: "reference-00.png",
              portrait_source_revision_id: photoIds.sourceRevision,
              portrait_artifact_id: photoIds.artifact,
              item_id: null,
              evidence_id: null,
              source_id: null,
              canonical_sha256: photoBytesSha256,
              media_type: "image/png",
              byte_length: photoBytes.length,
              width: 2,
              height: 2,
            },
            ...outfit.members.map((member, index) => ({
              ordinal: index + 1,
              role: "garment" as const,
              transmitted_filename: `reference-${String(index + 1).padStart(2, "0")}.png`,
              portrait_source_revision_id: null,
              portrait_artifact_id: null,
              item_id: member.item_id,
              evidence_id: `96000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
              source_id: `97000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
              canonical_sha256: photoBytesSha256,
              media_type: "image/png",
              byte_length: photoBytes.length,
              width: 2,
              height: 2,
            })),
          ],
          retention: {
            revision: "p08-openai-image-edits-disclosure-v1",
            declaration: request.retention,
            images_api_has_application_state_retention: false,
            default_abuse_monitoring_max_days: 30,
            model_is_zdr_compatible: true,
            compatibility_is_not_project_enrollment: true,
            csam_input_scanning_applies: true,
            flagged_inputs_may_be_retained_for_review: true,
          },
        },
        approval: {
          approval_id: approvalId,
          outfit_id: outfit.outfit_id,
          expires_at: "2026-07-15T00:10:00Z",
          single_use: true,
          garment_count: outfit.members.length,
          asset_snapshot_sha256: photoBytesSha256,
          outfit_revision: outfitRevision,
        },
        replay_status: "created",
      } as T;
    }

    case "submit_try_on_v1": {
      const outfit = savedOutfits[0];
      if (!outfit) throw commandError("not_found");
      tryOnState = {
        approvalId: String(request.approval_id),
        jobId: "95000000-0000-4000-8000-000000000002",
        outfitId: outfit.outfit_id,
        state: "queued",
      };
      saveTryOnState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        job: tryOnJob(tryOnState),
        replay_status: "created",
      } as T;
    }

    case "get_outfit_try_on_v1": {
      const outfit = savedOutfits.find(
        (candidate) => candidate.outfit_id === request.outfit_id,
      );
      if (!outfit) throw commandError("not_found");
      if (
        tryOnState &&
        tryOnState.outfitId === outfit.outfit_id &&
        recoveredTryOnAfterReload
      ) {
        tryOnState = { ...tryOnState, state: "succeeded" };
        saveTryOnState();
      }
      const active =
        tryOnState?.outfitId === outfit.outfit_id ? tryOnState : null;
      return {
        schema_version: 1,
        request_id: request.request_id,
        outfit_id: outfit.outfit_id,
        outfit_name: outfit.name,
        latest_job: active ? tryOnJob(active) : null,
        output:
          active?.state === "succeeded"
            ? {
                job_id: active.jobId,
                outfit_id: outfit.outfit_id,
                media_type: "image/png",
                width: 1024,
                height: 1536,
                bytes_sha256: photoBytesSha256,
                bytes: photoBytes,
                use_class: "presentation_only",
                eligible_as_evidence: false,
                label:
                  "AI visualization. Not an accurate representation of fit or garment construction.",
                created_at: "2026-07-15T00:01:00Z",
              }
            : null,
        garment_sources: active
          ? outfit.members.map((member, index) => ({
              ordinal: index + 1,
              item_id: member.item_id,
              item_updated_revision: member.item_updated_revision,
              attributes: member.attributes,
              evidence_id: `96000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
              source_id: `97000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
              media_type: "image/png",
              width: 2,
              height: 2,
              bytes_sha256: photoBytesSha256,
              bytes: photoBytes,
            }))
          : [],
        try_on_revision: active ? 2 : 0,
      } as T;
    }

    case "list_catalog_v1": {
      const offset = cursorOffset(request.cursor);
      return {
        schema_version: 1,
        request_id: request.request_id,
        items: items.slice(offset, offset + pageSize).map(toWireItem),
        total_count: items.length,
        catalog_revision: revision,
        evidence_generation: 4,
        next_cursor:
          offset + pageSize < items.length
            ? `catalog:${offset + pageSize}`
            : null,
        roots,
      } as T;
    }

    case "list_inbox_v1": {
      const state = String(request.state);
      const matching = evidence.filter((row) => row.state === state);
      const offset = cursorOffset(request.cursor);
      const page = matching.slice(offset, offset + pageSize);
      return {
        schema_version: 1,
        request_id: request.request_id,
        evidence:
          state === "quarantine"
            ? []
            : page.map(toWireEvidence),
        quarantines:
          state === "quarantine"
            ? page.map(toWireQuarantine)
            : [],
        total_count: matching.length,
        catalog_revision: revision,
        evidence_generation: 4,
        next_cursor:
          offset + pageSize < matching.length
            ? `inbox:${offset + pageSize}`
            : null,
      } as T;
    }

    case "create_manual_outfit_v1": {
      if (
        request.expected_catalog_revision !== revision ||
        request.expected_outfit_revision !== outfitRevision
      ) {
        throw commandError("request_conflict");
      }
      const itemIds = request.item_ids as string[];
      if (
        !Array.isArray(itemIds) ||
        itemIds.length < 2 ||
        itemIds.length > 8 ||
        new Set(itemIds).size !== itemIds.length
      ) {
        throw commandError("invalid_request");
      }
      const selected = itemIds.map((id) =>
        items.find((candidate) => candidate.item_id === id),
      );
      if (selected.some((value) => !value)) {
        throw commandError("request_conflict");
      }
      outfitRevision += 1;
      const outfit: OutfitV1 = {
        outfit_id: `93000000-0000-4000-8000-${String(outfitRevision).padStart(12, "0")}`,
        name: String(request.name),
        members: selected.map((value, ordinal) => ({
          ordinal,
          item_id: value!.item_id,
          item_updated_revision: revision,
          attributes: toWireItem(value!).attributes,
          asset: {
            state: "metadata_only",
            evidence_id: null,
            source_id: null,
            blob_sha256: null,
            media_type: null,
            byte_length: null,
            width: null,
            height: null,
          },
        })),
        created_outfit_revision: outfitRevision,
      };
      savedOutfits.unshift(outfit);
      saveOutfitState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        outfit,
        outfit_revision: outfitRevision,
        replay_status: "created",
      } as T;
    }

    case "list_outfits_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        outfits: savedOutfits,
        total_count: savedOutfits.length,
        outfit_revision: outfitRevision,
        next_cursor: null,
      } as T;

    case "get_outfit_collage_v1": {
      const outfit = savedOutfits.find(
        (candidate) => candidate.outfit_id === request.outfit_id,
      );
      if (!outfit) throw commandError("not_found");
      return {
        schema_version: 1,
        request_id: request.request_id,
        outfit_id: outfit.outfit_id,
        name: outfit.name,
        members: outfit.members.map((member) => ({ member, bytes: null })),
        outfit_revision: outfitRevision,
      } as T;
    }

    case "list_imported_photo_roots_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        roots: [
          {
            import_root_id: photoIds.root,
            completed_scan_id: photoIds.scan,
            manifest_generation: 12,
            member_count: 3,
            eligible_count: 2,
            quarantined_count: 1,
          },
        ],
        total_count: 1,
        evidence_generation: 4,
        next_cursor: null,
      } as T;

    case "create_photo_scope_v1":
      if (
        request.import_root_id !== photoIds.root ||
        request.expected_manifest_generation !== 12
      ) {
        throw commandError("invalid_request");
      }
      photoState.scopeCreated = true;
      persistPhotoState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        scope: photoScope(),
        replay_status: "created",
      } as T;

    case "detect_photo_scope_people_v1":
      assertPhotoScope(request);
      photoState.detected = true;
      photoState.photoRevision += 1;
      persistPhotoState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        scope_id: photoIds.scope,
        run_id: photoIds.detectionRun,
        state: "completed",
        member_count: 3,
        completed_count: 3,
        terminal_review_count: 2,
        instances_available_count: 1,
        no_person_detected_count: 0,
        overflow_count: 0,
        retryable_failure_count: 1,
        permanent_unavailable_count: 0,
        skipped_count: 1,
        photo_revision: photoState.photoRevision,
        owner_revision: photoState.ownerRevision,
        evidence_generation: 4,
        replay_status: "created",
      } as T;

    case "list_photo_owner_reviews_v1": {
      const state = String(request.state) as PhotoOwnerReviewStateV1;
      const reviews =
        !photoState.detected
          ? []
          : state === "instances_available"
            ? [photoOwnerReview()]
            : state === "retryable_failure"
              ? [photoFailureReview()]
              : [];
      return {
        schema_version: 1,
        request_id: request.request_id,
        state,
        reviews,
        next_cursor: null,
        photo_revision: photoState.photoRevision,
        owner_revision: photoState.ownerRevision,
      } as T;
    }

    case "read_photo_owner_preview_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        owner_review_id: request.owner_review_id,
        preview_id: request.preview_id,
        media_type: "image/png",
        width: 320,
        height: 240,
        byte_length: photoBytes.length,
        bytes_sha256: photoBytesSha256,
        bytes: photoBytes,
      } as T;

    case "correct_photo_person_detection_v1": {
      assertOwnerRevisions(request);
      photoState.manualPersonAdded = true;
      photoState.detectionRevision += 1;
      photoState.photoRevision += 1;
      persistPhotoState();
      const review = photoOwnerReview();
      const instance = review.instances.at(-1);
      return {
        schema_version: 1,
        request_id: request.request_id,
        review,
        instance,
        replay_status: "created",
      } as T;
    }

    case "decide_photo_owner_v1": {
      assertOwnerRevisions(request);
      photoState.ownerConfirmed = request.action === "select_person";
      photoState.ownerRevision += 1;
      photoState.photoRevision += 1;
      persistPhotoState();
      return ownerDecisionResponse(request, false) as T;
    }

    case "correct_photo_owner_v1": {
      assertOwnerRevisions(request);
      photoState.ownerConfirmed = request.action === "select_person";
      photoState.ownerRevision += 1;
      photoState.photoRevision += 1;
      persistPhotoState();
      return ownerDecisionResponse(request, true) as T;
    }

    case "retry_photo_person_detection_v1":
      assertOwnerRevisions(request);
      photoState.detectionRevision += 1;
      photoState.photoRevision += 1;
      persistPhotoState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        owner_review_id: request.owner_review_id,
        detection_revision: photoState.detectionRevision,
        owner_revision: photoState.ownerRevision,
        photo_revision: photoState.photoRevision,
        replay_status: "created",
      } as T;

    case "analyze_photo_scope_v1":
      assertPhotoScope(request);
      if (!photoState.ownerConfirmed) {
        throw commandError("invalid_state");
      }
      photoState.analyzed = true;
      photoState.observationState = "needs_review";
      photoState.photoRevision += 1;
      persistPhotoState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        scope_id: photoIds.scope,
        run_id: photoIds.run,
        state: "completed",
        member_count: 3,
        completed_count: 3,
        needs_review_count: 1,
        skipped_count: 1,
        failed_count: 0,
        photo_revision: photoState.photoRevision,
        evidence_generation: 4,
        replay_status: "created",
      } as T;

    case "list_photo_observations_v1": {
      assertPhotoScope(request);
      const state = String(request.state) as PhotoObservationStateV1;
      const observations =
        photoState.analyzed && state === photoState.observationState
          ? [photoObservation()]
          : [];
      return {
        schema_version: 1,
        request_id: request.request_id,
        scope_id: photoIds.scope,
        state,
        observations,
        total_count: observations.length,
        photo_revision: photoState.photoRevision,
        evidence_generation: 4,
        next_cursor: null,
      } as T;
    }

    case "read_photo_artifact_v1":
      if (request.artifact_id !== photoState.artifactId) {
        throw commandError("not_found");
      }
      return {
        schema_version: 1,
        request_id: request.request_id,
        artifact_id: photoState.artifactId,
        media_type: "image/png",
        width: 320,
        height: 240,
        bytes_sha256: photoBytesSha256,
        bytes: photoBytes,
      } as T;

    case "prompt_photo_observation_v1": {
      assertPhotoObservation(request);
      const rectangle = request.box_rectangle as RectV1;
      assertPhotoRectangle(rectangle);
      photoState.rectangle = rectangle;
      photoState.promptSequence += 1;
      photoState.artifactId = `91000000-0000-4000-8000-${String(
        7 + photoState.promptSequence,
      ).padStart(12, "0")}`;
      photoState.photoRevision += 1;
      persistPhotoState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        observation: photoObservation(),
        photo_revision: photoState.photoRevision,
        evidence_generation: 4,
        replay_status: "created",
      } as T;
    }

    case "review_photo_observation_v1": {
      assertPhotoObservation(request);
      if (request.expected_photo_revision !== photoState.photoRevision) {
        throw commandError("request_conflict");
      }
      const action = String(request.action) as PhotoReviewActionV1;
      const replacement = (request.replacement_rectangle as RectV1 | null) ?? null;
      if (
        (action === "replace_crop" && !replacement) ||
        (action !== "replace_crop" && replacement)
      ) {
        throw commandError("invalid_request");
      }
      if (replacement) {
        assertPhotoRectangle(replacement);
        photoState.rectangle = replacement;
        photoState.artifactId = "91000000-0000-4000-8000-000000000099";
      }
      photoState.reviewAction = action;
      photoState.observationState = photoReviewState(action);
      photoState.photoRevision += 1;
      persistPhotoState();
      const decision = photoDecision(action);
      return {
        schema_version: 1,
        request_id: request.request_id,
        observation: photoObservation(),
        decision,
        new_photo_revision: photoState.photoRevision,
        replay_status: "created",
      } as T;
    }

    case "open_reconciliation_case_v1": {
      assertPhotoObservation(request);
      if (
        !["confirmed", "replaced"].includes(photoState.observationState) ||
        request.selected_artifact_id !== photoState.artifactId ||
        request.expected_photo_revision !== photoState.photoRevision
      ) {
        throw commandError("request_conflict");
      }
      reconciliationRevision += 1;
      return {
        schema_version: 1,
        request_id: request.request_id,
        case: reconciliationCase(),
        evidence_generation: 4,
        reconciliation_revision: reconciliationRevision,
        replay_status: "created",
      } as T;
    }

    case "list_reconciliation_cases_v2":
      return {
        schema_version: 2,
        request_id: request.request_id,
        observation_id: photoIds.observation,
        state: request.state,
        cases: reconciliationOpened ? [reconciliationCase()] : [],
        next_cursor: null,
        photo_revision: photoState.photoRevision,
        owner_revision: photoState.ownerRevision,
        reconciliation_revision: reconciliationRevision,
      } as T;

    case "open_reconciliation_case_v2": {
      assertPhotoObservation(request);
      if (
        !["confirmed", "replaced"].includes(photoState.observationState) ||
        request.selected_artifact_id !== photoState.artifactId ||
        request.expected_photo_revision !== photoState.photoRevision ||
        request.expected_owner_revision !== photoState.ownerRevision
      ) {
        throw commandError("request_conflict");
      }
      reconciliationOpened = true;
      reconciliationRevision += 1;
      return {
        schema_version: 2,
        request_id: request.request_id,
        case: reconciliationCase(),
        evidence_generation: 4,
        photo_revision: photoState.photoRevision,
        owner_revision: photoState.ownerRevision,
        reconciliation_revision: reconciliationRevision,
        replay_status: "created",
      } as T;
    }

    case "decide_reconciliation_case_v1": {
      if (
        request.case_id !== reconciliationIds.case ||
        request.expected_case_revision !== reconciliationCaseRevision
      ) {
        throw commandError("request_conflict");
      }
      const outcome = String(request.outcome) as ReconciliationOutcomeV1;
      const selectedCandidateId =
        (request.selected_candidate_id as string | null) ?? null;
      if (!validReconciliationDecision(outcome, selectedCandidateId)) {
        throw commandError("invalid_request");
      }
      reconciliationCaseRevision += 1;
      reconciliationRevision += 1;
      reconciliationDecisionSequence += 1;
      reconciliationDecisionHead = {
        decision_id: `92000000-0000-4000-8000-${String(
          100 + reconciliationDecisionSequence,
        ).padStart(12, "0")}`,
        case_id: reconciliationIds.case,
        outcome,
        selected_candidate_id: selectedCandidateId,
        case_revision: reconciliationCaseRevision,
      };
      return {
        schema_version: 1,
        request_id: request.request_id,
        case: reconciliationCase(),
        decision: reconciliationDecisionHead,
        reconciliation_revision: reconciliationRevision,
        replay_status: "created",
      } as T;
    }

    case "decide_reconciliation_case_v2": {
      if (
        request.case_id !== reconciliationIds.case ||
        request.expected_case_revision !== reconciliationCaseRevision ||
        request.expected_owner_revision !== photoState.ownerRevision ||
        request.expected_photo_revision !== photoState.photoRevision ||
        request.expected_reconciliation_revision !== reconciliationRevision
      ) {
        throw commandError("request_conflict");
      }
      const outcome = String(request.outcome) as ReconciliationOutcomeV1;
      const selectedCandidateId =
        (request.selected_candidate_id as string | null) ?? null;
      if (!validReconciliationDecision(outcome, selectedCandidateId)) {
        throw commandError("invalid_request");
      }
      reconciliationCaseRevision += 1;
      reconciliationRevision += 1;
      reconciliationDecisionSequence += 1;
      reconciliationDecisionHead = {
        decision_id: `92000000-0000-4000-8000-${String(
          100 + reconciliationDecisionSequence,
        ).padStart(12, "0")}`,
        case_id: reconciliationIds.case,
        outcome,
        selected_candidate_id: selectedCandidateId,
        case_revision: reconciliationCaseRevision,
      };
      return {
        schema_version: 2,
        request_id: request.request_id,
        case: reconciliationCase(),
        decision: reconciliationDecisionHead,
        photo_revision: photoState.photoRevision,
        owner_revision: photoState.ownerRevision,
        reconciliation_revision: reconciliationRevision,
        replay_status: "created",
      } as T;
    }

    case "list_receipts_v1": {
      const state = String(request.state) as ReceiptStateV1;
      const matching = receiptSummaries().filter(
        (receipt) => receipt.state === state,
      );
      const offset = cursorOffset(request.cursor);
      return {
        schema_version: 1,
        request_id: request.request_id,
        receipts: matching.slice(offset, offset + pageSize),
        total_count: matching.length,
        receipt_revision: receiptState.receiptRevision,
        evidence_generation: 4,
        next_cursor:
          offset + pageSize < matching.length
            ? `receipts:${offset + pageSize}`
            : null,
      } as T;
    }

    case "list_receipt_image_candidates_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        source_id: request.source_id,
        candidates: [
          {
            candidate_id: "78000000-0000-4000-8000-000000000001",
            source_id: request.source_id,
            display_host: "images.example.test",
            candidate_url_sha256: "a".repeat(64),
            eligibility: "eligible",
            latest_attempt: null,
          },
        ],
        omitted_count: 0,
      } as T;

    case "approve_and_fetch_receipt_image_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        candidate_id: request.candidate_id,
        attempt_id: "78000000-0000-4000-8000-000000000002",
        outcome: "succeeded",
        failure_code: null,
        artifact: {
          image_id: "78000000-0000-4000-8000-000000000003",
          source_blob_sha256: "b".repeat(64),
          source_byte_length: 1024,
          source_media_type: "image/png",
          display_blob_sha256: "c".repeat(64),
          display_byte_length: 900,
          display_media_type: "image/png",
          width: 640,
          height: 800,
          policy_revision: "receipt-image-network-policy-v1",
          decoder_revision: "image-0.25.10-v1",
          derivative_revision: "png-rgba8-best-paeth-v1",
        },
        replay_status: "created",
      } as T;

    case "analyze_receipt_v1": {
      if (request.source_id !== receiptIds.source) {
        throw commandError("not_found");
      }
      receiptState.analyzed = true;
      receiptState.state = "needs_review";
      receiptState.receiptRevision += 1;
      persistReceiptState();
      const order = currentReceiptOrder();
      return {
        schema_version: 1,
        request_id: request.request_id,
        parsed: structuredClone(parsedReceiptFixture),
        order,
        processing: structuredClone(processingFixture),
        state: receiptState.state,
        receipt_revision: receiptState.receiptRevision,
        evidence_generation: 4,
        replay_status: "created",
      } as T;
    }

    case "review_receipt_v1": {
      if (request.order_evidence_id !== receiptIds.order) {
        throw commandError("not_found");
      }
      if (request.expected_receipt_revision !== receiptState.receiptRevision) {
        throw commandError("request_conflict");
      }
      const action = String(request.action) as ReceiptReviewActionV1;
      const correctedOrder =
        (request.corrected_order as CorrectedReceiptOrderV1 | null) ?? null;
      if (
        (action === "correct" && !correctedOrder) ||
        (action !== "correct" && correctedOrder)
      ) {
        throw commandError("invalid_request");
      }
      receiptState.receiptRevision += 1;
      receiptState.reviewSequence += 1;
      receiptState.state = reviewState(action);
      receiptState.correctedOrder = correctedOrder;
      persistReceiptState();
      const decision = currentReceiptDecision(action);
      return {
        schema_version: 1,
        request_id: request.request_id,
        order: currentReceiptOrder(decision),
        decision,
        new_receipt_revision: receiptState.receiptRevision,
        evidence_generation: 4,
        replay_status: "created",
      } as T;
    }

    case "import_local_sources_v1":
    case "refresh_import_roots_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        summaries: [
          {
            source_id: "41000000-0000-4000-8000-000000000001",
            import_root_id: roots[0]?.root_id ?? null,
            imported: 2,
            reused: 1,
            quarantined: 1,
            skipped: 0,
            unavailable: 0,
          },
        ],
        evidence_generation: 5,
        replay_status: "created",
      } as T;

    case "save_item_v1": {
      assertRevision(request);
      const attributes = request.attributes as CatalogItem;
      const itemId = request.item_id as string | null;
      const decisionId = nextDecision(items);
      if (itemId) {
        items = items.map((value) =>
          value.item_id === itemId
            ? {
                ...value,
                ...attributes,
                updated_at: new Date().toISOString(),
                last_decision_id: decisionId,
              }
            : value,
        );
      } else {
        items = [
          ...items,
          {
            ...attributes,
            item_id: crypto.randomUUID(),
            evidence_ids: (request.evidence_ids as string[]) ?? [],
            updated_at: new Date().toISOString(),
            last_decision_id: decisionId,
          },
        ];
      }
      const changed =
        items.find((value) => value.item_id === itemId) ??
        items.at(-1)!;
      return mutationResponse(
        request,
        decisionId,
        "save_item",
        { item: toWireItem(changed) },
      ) as T;
    }

    case "decide_evidence_v1": {
      assertRevision(request);
      const evidenceId = String(request.evidence_id);
      const decision = String(request.action);
      const decisionId = nextDecision(items);
      if (decision === "assign") {
        const itemId = String(request.item_id);
        items = items.map((value) =>
          value.item_id === itemId
            ? {
                ...value,
                evidence_ids: [...value.evidence_ids, evidenceId],
                last_decision_id: decisionId,
              }
            : value,
        );
      }
      if (decision !== "defer") {
        evidence = evidence.filter((row) => row.evidence_id !== evidenceId);
      }
      const changed =
        evidence.find((row) => row.evidence_id === evidenceId) ??
        evidenceRow(evidenceId, "Processed evidence", "image");
      return mutationResponse(
        request,
        decisionId,
        "decide_evidence",
        { evidence: toWireEvidence(changed) },
      ) as T;
    }

    case "merge_items_v1": {
      assertRevision(request);
      const ids = request.item_ids as string[];
      const selected = items.filter((value) => ids.includes(value.item_id));
      const decisionId = nextDecision(items);
      const attributes = request.target_attributes as CatalogItem;
      items = [
        ...items.filter((value) => !ids.includes(value.item_id)),
        {
          ...attributes,
          item_id: selected[0]?.item_id ?? crypto.randomUUID(),
          evidence_ids: selected.flatMap((value) => value.evidence_ids),
          updated_at: new Date().toISOString(),
          last_decision_id: decisionId,
        },
      ];
      const merged = items.find(
        (value) => value.last_decision_id === decisionId,
      )!;
      return mutationResponse(
        request,
        decisionId,
        "merge_items",
        { item: toWireItem(merged) },
      ) as T;
    }

    case "split_item_v1": {
      assertRevision(request);
      const source = items.find((value) => value.item_id === request.item_id);
      if (!source) throw commandError("not_found");
      const groups = request.groups as Array<{
        attributes: CatalogItem;
        evidence_ids: string[];
      }>;
      const decisionId = nextDecision(items);
      items = [
        ...items.filter((value) => value.item_id !== source.item_id),
        ...groups.map((group, index) => ({
          ...source,
          ...group.attributes,
          item_id: index === 0 ? source.item_id : crypto.randomUUID(),
          evidence_ids: group.evidence_ids,
          updated_at: new Date().toISOString(),
          last_decision_id: decisionId,
        })),
      ];
      const splitItems = items.filter(
        (value) => value.last_decision_id === decisionId,
      );
      return mutationResponse(
        request,
        decisionId,
        "split_item",
        { items: splitItems.map(toWireItem) },
      ) as T;
    }

    case "undo_decision_v1": {
      assertRevision(request);
      const snapshot = undoSnapshots.get(String(request.decision_id));
      if (!snapshot) throw commandError("not_found");
      const decisionId = nextDecision(items);
      items = structuredClone(snapshot).map((value) => ({
        ...value,
        last_decision_id: decisionId,
      }));
      return mutationResponse(
        request,
        decisionId,
        "undo",
        { restored_items: items.map(toWireItem) },
      ) as T;
    }

    case "preview_deletion_v1": {
      const revisions = {
        catalog_revision: revision,
        evidence_generation: revision,
        receipt_revision: receiptState.receiptRevision,
        photo_revision: photoState.photoRevision,
        reconciliation_revision: reconciliationRevision,
        outfit_revision: outfitRevision,
        try_on_revision: 0,
      };
      pendingDeletionPlan = {
        itemId: String(request.target_id),
        token: "preview-1",
        planSha256: "a".repeat(64),
        revisions,
      };
      const firstClass: DeletionDependencyClassV1 = "evidence_records";
      const firstRows = deletionRows[firstClass];
      return {
        schema_version: 1,
        request_id: request.request_id,
        preview_snapshot_token: "preview-1",
        plan_sha256: "a".repeat(64),
        prepared_at: "2026-07-15T00:00:00Z",
        expires_at: "2026-07-15T00:15:00Z",
        revisions,
        overall_count: 6,
        retained_shared_blob_count: 1,
        unique_blob_count: 2,
        unique_blob_bytes: 4096,
        backup_retention: [],
        remote_retention: [],
        counts: Object.entries(deletionRows).map(([className, rows]) => ({
          class: className,
          count: BigInt(rows.length),
        })),
        first_class: firstClass,
        first_page: deletionPage(firstClass, firstRows, 0),
        next_cursor:
          firstRows.length > pageSize ? `${firstClass}:${pageSize}` : null,
      } as T;
    }

    case "execute_deletion_v1": {
      const envelope = JSON.stringify(request);
      if (deletionReceipt?.requestId === String(request.request_id)) {
        if (deletionReceipt.envelope !== envelope) {
          throw commandError("request_conflict");
        }
        return { ...deletionReceipt.response, replay_status: "replayed" } as T;
      }
      if (
        !pendingDeletionPlan ||
        request.preview_snapshot_token !== pendingDeletionPlan.token ||
        request.plan_sha256 !== pendingDeletionPlan.planSha256 ||
        request.confirmation !== "delete_active_local_data" ||
        JSON.stringify(request.expected_revisions) !==
          JSON.stringify(pendingDeletionPlan.revisions)
      ) {
        throw commandError("snapshot_expired");
      }
      items = items.filter(
        (item) => item.item_id !== pendingDeletionPlan?.itemId,
      );
      pendingDeletionPlan = null;
      revision += 1;
      const response = {
        schema_version: 1,
        request_id: request.request_id,
        run_id: crypto.randomUUID(),
        complete: true,
        accepted_at: "2026-07-15T00:01:00Z",
        deadline_at: "2026-07-15T01:01:00Z",
        completed_at: "2026-07-15T00:01:01Z",
        deleted_local_record_count: 6,
        deleted_unique_blob_count: 2,
        deleted_unique_blob_bytes: 4096,
        retained_shared_blob_count: 1,
        backup_retention: [],
        remote_retention: [],
        replay_status: "created",
      };
      deletionReceipt = {
        requestId: String(request.request_id),
        envelope,
        response,
      };
      return response as T;
    }

    case "list_deletion_plan_items_v1": {
      const className = String(
        request.class,
      ) as DeletionDependencyClassV1;
      const rows = deletionRows[className] ?? [];
      const offset = cursorOffset(request.cursor);
      return {
        schema_version: 1,
        request_id: request.request_id,
        preview_snapshot_token: request.preview_snapshot_token,
        class: className,
        items: deletionPage(className, rows, offset),
        total_count: rows.length,
        next_cursor:
          offset + pageSize < rows.length
            ? `${className}:${offset + pageSize}`
            : null,
      } as T;
    }

    case "get_gmail_connector_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        settings: gmailState.settings,
        status: gmailState.status,
        user_action:
          gmailState.status === "not_configured"
            ? "configure_gmail"
            : gmailState.status === "connected"
              ? "none"
              : "connect_gmail",
      } as T;

    case "save_gmail_settings_v1":
      gmailState = {
        settings: {
          provider_profile: "google",
          oauth_client_id: String(request.client_id),
          label_name: String(request.label_name),
          limits: structuredClone(
            request.limits as GmailConnectorSettingsV1["limits"],
          ),
        },
        status: "disconnected",
      };
      persistGmailState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        settings: gmailState.settings,
        status: "disconnected",
        user_action: "connect_gmail",
        replay_status: "created",
      } as T;

    case "connect_gmail_v1":
      if (!gmailState.settings) throw commandError("invalid_state");
      gmailState.status = "connected";
      if (
        !evidence.some(
          (row) => row.evidence_id === "30000000-0000-4000-8000-000000000006",
        )
      ) {
        evidence.unshift(
          evidenceRow(
            "30000000-0000-4000-8000-000000000006",
            "Gmail purchase: Linen overshirt",
            "email",
          ),
        );
      }
      persistGmailState();
      return gmailSyncResponse(request, 1, 0) as T;

    case "sync_gmail_v1":
      if (gmailState.status !== "connected") {
        throw commandError("invalid_state");
      }
      return gmailSyncResponse(request, 0, 1) as T;

    case "disconnect_gmail_v1":
      if (gmailState.status !== "connected") {
        throw commandError("invalid_state");
      }
      gmailState.status = "disconnected";
      persistGmailState();
      return {
        schema_version: 1,
        request_id: request.request_id,
        status: "disconnected",
        user_action: "connect_gmail",
        revocation_outcome: "failed",
        replay_status: "created",
      } as T;

    case "run_storage_check_v1":
      return {
        schema_version: 1,
        request_id: request.request_id,
        check_id: crypto.randomUUID(),
        job_id: crypto.randomUUID(),
        replay_status: "created",
      } as T;

    case "save_credential_v1":
    case "delete_credential_v1":
      return { schema_version: 1, request_id: request.request_id } as T;

    default:
      throw commandError("not_found");
  }
};

function item(
  itemId: string,
  displayName: string,
  category: CatalogItem["category"],
  color: string,
  evidenceIds: string[],
): CatalogItem {
  return {
    item_id: itemId,
    display_name: displayName,
    category,
    color,
    notes: "",
    evidence_ids: evidenceIds,
    updated_at: "2026-07-15T00:00:00Z",
    last_decision_id: null,
  };
}

function evidenceRow(
  evidenceId: string,
  displayName: string,
  kind: Evidence["kind"],
): Evidence {
  return {
    evidence_id: evidenceId,
    state: "unresolved",
    kind,
    display_name: displayName,
    source_label: kind === "email" ? "orders.mbox" : "Pictures/Wardrobe",
    imported_at: "2026-07-15T00:00:00Z",
    quarantine_reason: null,
    decision_capable: true,
  };
}

function cursorOffset(cursor: unknown): number {
  if (typeof cursor !== "string") return 0;
  const value = Number(cursor.split(":").at(-1));
  return Number.isFinite(value) ? value : 0;
}

function nextDecision(snapshot: CatalogItem[]): string {
  const id = `50000000-0000-4000-8000-${String(decisionSequence++).padStart(12, "0")}`;
  undoSnapshots.set(id, structuredClone(snapshot));
  revision += 1;
  return id;
}

function mutationResponse(
  request: Request,
  decisionId: string,
  kind: DecisionKindV1,
  value: Record<string, unknown>,
) {
  return {
    schema_version: 1,
    request_id: request.request_id,
    ...value,
    decision: {
      decision_id: decisionId,
      kind,
      affected_item_ids: items
        .filter((item) => item.last_decision_id === decisionId)
        .map((item) => item.item_id),
      affected_evidence_ids: [],
      compensates_decision_id: null,
      reversible: true,
    },
    new_catalog_revision: revision,
    replay_status: "created",
  };
}

function assertRevision(request: Request) {
  if (request.expected_catalog_revision !== revision) {
    throw commandError("request_conflict");
  }
}

function commandError(code: string) {
  return {
    schema_version: 1,
    code,
    retryable: false,
    user_action: code === "request_conflict" ? "start_new_request" : "retry",
    field: null,
  };
}

function loadPersistedCalls(): Array<{ command: string; request: Request }> {
  try {
    const stored = sessionStorage.getItem(callStorageKey);
    return stored
      ? JSON.parse(stored) as Array<{ command: string; request: Request }>
      : [];
  } catch {
    return [];
  }
}

function loadOutfitState(): PersistedOutfitState {
  const fallback: PersistedOutfitState = {
    outfitRevision: 0,
    savedOutfits: [],
  };
  try {
    const stored = sessionStorage.getItem(outfitStorageKey);
    return stored
      ? { ...fallback, ...(JSON.parse(stored) as PersistedOutfitState) }
      : fallback;
  } catch {
    return fallback;
  }
}

function saveOutfitState() {
  sessionStorage.setItem(
    outfitStorageKey,
    JSON.stringify({ outfitRevision, savedOutfits }),
  );
}

function loadTryOnState(): PersistedTryOnState | null {
  try {
    const stored = sessionStorage.getItem(tryOnStorageKey);
    return stored ? JSON.parse(stored) as PersistedTryOnState : null;
  } catch {
    return null;
  }
}

function saveTryOnState() {
  if (tryOnState) {
    sessionStorage.setItem(tryOnStorageKey, JSON.stringify(tryOnState));
  }
}

function tryOnJob(state: PersistedTryOnState) {
  const succeeded = state.state === "succeeded";
  return {
    job_id: state.jobId,
    approval_id: state.approvalId,
    outfit_id: state.outfitId,
    state: state.state,
    attempt_count: succeeded ? 1 : 0,
    created_at: "2026-07-15T00:00:00Z",
    updated_at: succeeded
      ? "2026-07-15T00:01:00Z"
      : "2026-07-15T00:00:00Z",
    completed_at: succeeded ? "2026-07-15T00:01:00Z" : null,
    failure: null,
  };
}

function loadReceiptState(): PersistedReceiptState {
  const fallback: PersistedReceiptState = {
    analyzed: false,
    state: "unanalyzed",
    correctedOrder: null,
    receiptRevision: 12,
    reviewSequence: 0,
  };
  try {
    const stored = sessionStorage.getItem(receiptStorageKey);
    return stored
      ? { ...fallback, ...JSON.parse(stored) as PersistedReceiptState }
      : fallback;
  } catch {
    return fallback;
  }
}

function persistReceiptState() {
  sessionStorage.setItem(receiptStorageKey, JSON.stringify(receiptState));
}

function loadPhotoState(): PersistedPhotoState {
  const fallback: PersistedPhotoState = {
    scopeCreated: false,
    detected: false,
    analyzed: false,
    detectionRevision: 1,
    ownerRevision: 0,
    ownerConfirmed: false,
    manualPersonAdded: false,
    photoRevision: 20,
    observationState: "needs_review",
    reviewAction: null,
    rectangle: { x: 40, y: 30, width: 200, height: 160 },
    artifactId: "91000000-0000-4000-8000-000000000007",
    promptSequence: 0,
  };
  try {
    const stored = sessionStorage.getItem(photoStorageKey);
    return stored
      ? { ...fallback, ...JSON.parse(stored) as PersistedPhotoState }
      : fallback;
  } catch {
    return fallback;
  }
}

function persistPhotoState() {
  sessionStorage.setItem(photoStorageKey, JSON.stringify(photoState));
}

function loadGmailState(): PersistedGmailState {
  const fallback: PersistedGmailState = {
    settings: null,
    status: "not_configured",
  };
  try {
    const stored = sessionStorage.getItem(gmailStorageKey);
    return stored
      ? { ...fallback, ...(JSON.parse(stored) as PersistedGmailState) }
      : fallback;
  } catch {
    return fallback;
  }
}

function persistGmailState() {
  sessionStorage.setItem(gmailStorageKey, JSON.stringify(gmailState));
}

function gmailSyncResponse(
  request: Request,
  imported: number,
  updated: number,
) {
  return {
    schema_version: 1,
    request_id: request.request_id,
    status: "connected",
    user_action: "none",
    summary: {
      pages_scanned: 1,
      unique_messages: 1,
      messages_imported: imported,
      messages_updated: updated,
      messages_unavailable: 0,
      raw_bytes_read: 1024,
    },
    replay_status: "created",
  };
}

function photoScope() {
  return {
    scope_id: photoIds.scope,
    import_root_id: photoIds.root,
    completed_scan_id: photoIds.scan,
    manifest_generation: 12,
    member_count: 3,
    eligible_count: 2,
    quarantined_count: 1,
    membership_sha256: photoMembershipSha256,
  };
}

function photoOwnerReview() {
  const instances: PhotoPersonInstanceV1[] = [
    {
      person_instance_id: photoIds.person,
      owner_review_id: photoIds.ownerReview,
      source_revision_id: photoIds.sourceRevision,
      source_revision_sha256: "2".repeat(64),
      source_kind: "apple_vision" as const,
      rectangle: { x: 36, y: 18, width: 92, height: 190 },
      confidence_basis_points: 9600,
      provider_revision: "apple-vision-human-rectangles-v1",
    },
  ];
  if (photoState.manualPersonAdded) {
    instances.push({
      person_instance_id: photoIds.manualPerson,
      owner_review_id: photoIds.ownerReview,
      source_revision_id: photoIds.sourceRevision,
      source_revision_sha256: "2".repeat(64),
      source_kind: "manual_user_rectangle",
      rectangle: { x: 166, y: 24, width: 110, height: 190 },
      confidence_basis_points: null,
      provider_revision: null,
    });
  }
  return {
    owner_review_id: photoIds.ownerReview,
    source_revision_id: photoIds.sourceRevision,
    source_revision_sha256: "2".repeat(64),
    preview_id: photoIds.preview,
    terminal_attempt_id: photoIds.detectionAttempt,
    terminal_detection_state: "succeeded_instances" as const,
    state: "instances_available" as const,
    instances,
    provider_contract_revision: "local-person-detection-v1",
    provider_revision: "apple-vision-human-rectangles-v1",
    preprocessing_revision: "canonical-srgb-orientation-v1",
    vision_request_revision: 1,
    safe_reason_code: null,
    detection_revision: photoState.detectionRevision,
    owner_head_revision: photoState.ownerRevision,
    photo_revision: photoState.photoRevision,
  };
}

function photoFailureReview() {
  return {
    ...photoOwnerReview(),
    owner_review_id: photoIds.failureReview,
    preview_id: `${photoIds.preview.slice(0, -1)}8`,
    terminal_attempt_id: `${photoIds.detectionAttempt.slice(0, -1)}9`,
    terminal_detection_state: "retryable_failure" as const,
    state: "retryable_failure" as const,
    instances: [],
    safe_reason_code: "vision_request_failed",
  };
}

function ownerDecisionResponse(request: Request, correction: boolean) {
  const review = photoOwnerReview();
  return {
    schema_version: 1,
    request_id: request.request_id,
    review,
    decision: {
      owner_decision_id: correction
        ? `${photoIds.ownerDecision.slice(0, -1)}2`
        : photoIds.ownerDecision,
      owner_review_id: request.owner_review_id,
      action: request.action,
      selected_person_instance_id:
        request.selected_person_instance_id ?? null,
      supersedes_owner_decision_id: correction
        ? request.superseded_owner_decision_id
        : null,
      detection_revision: photoState.detectionRevision,
      owner_revision: photoState.ownerRevision,
      photo_revision: photoState.photoRevision,
    },
    replay_status: "created",
  };
}

function assertOwnerRevisions(request: Request) {
  if (
    !photoState.detected ||
    request.expected_detection_revision !== photoState.detectionRevision ||
    request.expected_owner_head_revision !== photoState.ownerRevision ||
    request.expected_photo_revision !== photoState.photoRevision
  ) {
    throw commandError("request_conflict");
  }
}

function photoObservation() {
  const action = photoState.reviewAction;
  const artifact = {
    artifact_id: photoState.artifactId,
    kind: "rectangle_source_crop" as const,
    artifact_schema_revision: "rectangle-source-crop-v1",
    artifact_revision: "crop-v1",
    scope_id: photoIds.scope,
    source_revision_id: photoIds.sourceRevision,
    source_revision_sha256: "2".repeat(64),
    input_blob_sha256: photoBytesSha256,
    media_type: "image/png" as const,
    source_width: 320,
    source_height: 240,
    rectangle: structuredClone(photoState.rectangle),
    preprocessing_revision: "canonical-srgb-v1",
    provider_contract_revision: "garment-segmentation-v1",
    provider_id: "unavailable-garment-segmentation-v1",
    provider_revision: "1",
    model_revision: null,
    request_mode: photoState.promptSequence > 0
      ? "interactive" as const
      : "automatic" as const,
    prompt_parameters_sha256: "3".repeat(64),
    quality_gate_revision: "automatic-mask-quality-v1",
    quality_approved: false,
    segmentation_outcome: "unavailable" as const,
    unavailable_reason: "reviewed_model_pack_absent" as const,
    failure_code: null,
    parent_artifact_ids: [],
    provenance_sha256: "4".repeat(64),
    artifact_sha256: "5".repeat(64),
  };
  return {
    observation_id: photoIds.observation,
    scope_id: photoIds.scope,
    source_revision_id: photoIds.sourceRevision,
    state: photoState.observationState,
    artifact,
    review_head: action
      ? {
          state: photoState.observationState,
          decision: photoDecision(action),
        }
      : null,
  };
}

function photoDecision(action: PhotoReviewActionV1) {
  return {
    decision_id: "91000000-0000-4000-8000-000000000010",
    observation_id: photoIds.observation,
    action,
    selected_artifact_id:
      action === "defer" || action === "reject" ? null : photoState.artifactId,
    photo_revision: photoState.photoRevision,
  };
}

function photoReviewState(
  action: PhotoReviewActionV1,
): PhotoObservationStateV1 {
  if (action === "confirm_crop") return "confirmed";
  if (action === "replace_crop") return "replaced";
  if (action === "defer") return "deferred";
  return "rejected";
}

function assertPhotoScope(request: Request) {
  if (!photoState.scopeCreated || request.scope_id !== photoIds.scope) {
    throw commandError("not_found");
  }
}

function assertPhotoObservation(request: Request) {
  if (
    !photoState.analyzed ||
    request.observation_id !== photoIds.observation
  ) {
    throw commandError("not_found");
  }
}

function assertPhotoRectangle(rectangle: RectV1) {
  if (
    !rectangle ||
    rectangle.x < 0 ||
    rectangle.y < 0 ||
    rectangle.width < 1 ||
    rectangle.height < 1 ||
    rectangle.x + rectangle.width > 320 ||
    rectangle.y + rectangle.height > 240
  ) {
    throw commandError("invalid_request");
  }
}

function reconciliationCase(): ReconciliationCaseV2 {
  return {
    case_id: reconciliationIds.case,
    observation_id: photoIds.observation,
    artifact_id: photoState.artifactId,
    artifact_sha256: "5".repeat(64),
    observation_date: "2026-07-14",
    retrieval_revision: "local-reconciliation-v1",
    candidates: [
      {
        candidate_id: reconciliationIds.receipt,
        target: {
          kind: "receipt_line",
          order_line_id: "92000000-0000-4000-8000-000000000020",
          variant_evidence_id: "92000000-0000-4000-8000-000000000021",
        },
        proposed_relation: "same_product_variant",
        observed_relations: [],
        rank: 2,
        display_name: "Merino overshirt",
        detail: "Northstar Outfitters · Charcoal · Medium",
        date: { kind: "purchase", value: "2026-04-03" },
        evidence: [
          {
            evidence_id: "92000000-0000-4000-8000-000000000030",
            polarity: "neutral",
            relation: "same_product_variant",
            feature: "receipt_review_state",
            source_kind: "receipt_review_decision",
            source_id: "92000000-0000-4000-8000-000000000040",
            source_revision: "receipt-r12",
            input_sha256: ["6".repeat(64)],
            extractor_id: "local-reconciliation-v1",
            extractor_revision: "1",
            value_code: "confirmed",
            measured_value: null,
          },
        ],
      },
      {
        candidate_id: reconciliationIds.wardrobeAlternative,
        target: {
          kind: "wardrobe_item",
          item_id: "10000000-0000-4000-8000-000000000002",
        },
        proposed_relation: "same_physical_item",
        observed_relations: [],
        rank: 3,
        display_name: "Navy field shirt",
        detail: "Wardrobe item without a comparison image",
        date: null,
        evidence: [
          {
            evidence_id: "92000000-0000-4000-8000-000000000031",
            polarity: "neutral",
            relation: "same_physical_item",
            feature: "catalog_image_status",
            source_kind: "catalog_decision",
            source_id: "92000000-0000-4000-8000-000000000041",
            source_revision: "catalog-r7",
            input_sha256: ["7".repeat(64)],
            extractor_id: "local-reconciliation-v1",
            extractor_revision: "1",
            value_code: "catalog_image_absent",
            measured_value: null,
          },
        ],
      },
      {
        candidate_id: reconciliationIds.noMatch,
        target: { kind: "no_match" },
        proposed_relation: null,
        observed_relations: [],
        rank: null,
        display_name: "No match",
        detail: "None of the local candidates",
        date: null,
        evidence: [],
      },
      {
        candidate_id: reconciliationIds.wardrobe,
        target: {
          kind: "wardrobe_item",
          item_id: "10000000-0000-4000-8000-000000000001",
        },
        proposed_relation: "same_physical_item",
        observed_relations: ["visual_similarity"],
        rank: 1,
        display_name: "White Oxford shirt",
        detail: "White cotton · Wardrobe",
        date: { kind: "catalog_created", value: "2026-05-12" },
        evidence: [
          {
            evidence_id: "92000000-0000-4000-8000-000000000032",
            polarity: "supporting",
            relation: "visual_similarity",
            feature: "difference_hash_distance",
            source_kind: "catalog_image_evidence",
            source_id: "92000000-0000-4000-8000-000000000042",
            source_revision: "catalog-r8",
            input_sha256: ["8".repeat(64), "9".repeat(64)],
            extractor_id: "local-visual-features-v1",
            extractor_revision: "1",
            value_code: "distance_measured",
            measured_value: 3,
          },
          {
            evidence_id: "92000000-0000-4000-8000-000000000033",
            polarity: "contradictory",
            relation: "visual_similarity",
            feature: "mean_color_distance",
            source_kind: "photo_artifact",
            source_id: photoState.artifactId,
            source_revision: "artifact-r4",
            input_sha256: ["8".repeat(64), "9".repeat(64)],
            extractor_id: "local-visual-features-v1",
            extractor_revision: "1",
            value_code: "distance_measured",
            measured_value: 212,
          },
        ],
      },
    ],
    leading_candidate_id: reconciliationIds.wardrobe,
    decision_head: reconciliationDecisionHead,
    case_revision: reconciliationCaseRevision,
    owner_decision_id: photoIds.ownerDecision,
    person_instance_id: photoState.manualPersonAdded
      ? photoIds.manualPerson
      : photoIds.person,
    owner_evidence_sha256: "7".repeat(64),
    owner_revision: photoState.ownerRevision,
    crop_decision_id: "91000000-0000-4000-8000-000000000010",
    crop_revision: photoState.photoRevision,
    source_revision_sha256: "2".repeat(64),
    authority_state: "open_eligible",
    authority_reason: "current_authority",
    created_at_ms: 1,
  };
}

function validReconciliationDecision(
  outcome: ReconciliationOutcomeV1,
  selectedCandidateId: string | null,
): boolean {
  if (outcome === "unresolved") return selectedCandidateId === null;
  if (outcome === "same_item") {
    return [
      reconciliationIds.wardrobe,
      reconciliationIds.wardrobeAlternative,
    ].includes(selectedCandidateId ?? "");
  }
  if (outcome === "same_variant") {
    return selectedCandidateId === reconciliationIds.receipt;
  }
  if (outcome === "different") {
    return [
      reconciliationIds.wardrobe,
      reconciliationIds.receipt,
      reconciliationIds.wardrobeAlternative,
    ].includes(selectedCandidateId ?? "");
  }
  return selectedCandidateId === reconciliationIds.noMatch;
}

function receiptSummaries() {
  const primary = receiptSummaryFixture(receiptState.state);
  primary.order_evidence_id = receiptState.analyzed ? receiptIds.order : null;
  primary.merchant = receiptState.analyzed ? "Northstar Outfitters" : null;
  primary.line_item_count = receiptState.analyzed ? 1 : 0;
  primary.processing = receiptState.analyzed
    ? structuredClone(processingFixture)
    : null;
  if (receiptState.reviewSequence > 0) {
    const action =
      receiptState.state === "confirmed"
        ? "confirm"
        : receiptState.state === "corrected"
          ? "correct"
          : receiptState.state === "deferred"
            ? "defer"
            : "reject";
    primary.review_head = {
      state: receiptState.state,
      decision: currentReceiptDecision(action),
    };
    if (receiptState.correctedOrder) {
      primary.merchant = receiptState.correctedOrder.merchant;
      primary.line_item_count = receiptState.correctedOrder.line_items.length;
    }
  }

  return [
    primary,
    {
      ...receiptSummaryFixture("unanalyzed"),
      source_id: "71000000-0000-4000-8000-000000000002",
      merchant: "Paper Trail",
    },
    {
      ...receiptSummaryFixture("unanalyzed"),
      source_id: "71000000-0000-4000-8000-000000000003",
      merchant: "Second Look",
    },
  ];
}

function currentReceiptDecision(
  action: ReceiptReviewActionV1,
): ReceiptReviewDecisionV1 {
  return {
    decision_id: `78000000-0000-4000-8000-${String(receiptState.reviewSequence).padStart(12, "0")}`,
    order_evidence_id: receiptIds.order,
    action,
    corrected_order:
      action === "correct"
        ? structuredClone(receiptState.correctedOrder)
        : null,
    receipt_revision: receiptState.receiptRevision,
    created_at: "2026-07-15T03:00:00Z",
  };
}

function currentReceiptOrder(
  decision?: ReceiptReviewDecisionV1,
) {
  const order = structuredClone(receiptOrderFixture);
  if (decision) {
    order.review_head = {
      state: receiptState.state,
      decision,
    };
  }
  return order;
}

function reviewState(action: ReceiptReviewActionV1): ReceiptStateV1 {
  if (action === "confirm") return "confirmed";
  if (action === "correct") return "corrected";
  if (action === "defer") return "deferred";
  return "rejected";
}

function toWireAttributes(item: CatalogItem): ItemAttributesV1 {
  return {
    display_name: item.display_name,
    category: item.category,
    subcategory: null,
    brand: null,
    primary_color: item.color || null,
    size: null,
    notes: item.notes || null,
    tags: [],
  };
}

function toWireItem(item: CatalogItem): CatalogItemV1 {
  return {
    item_id: item.item_id,
    attributes: toWireAttributes(item),
    evidence_ids: item.evidence_ids,
    last_decision_id:
      item.last_decision_id ??
      "50000000-0000-4000-8000-000000000000",
  };
}

function sourceFor(row: Evidence) {
  return {
    source_id: `60000000-0000-4000-8000-${row.evidence_id.slice(-12)}`,
    import_root_id:
      row.kind === "image" ? roots[0]?.root_id ?? null : null,
    parent_source_id: null,
    kind: row.kind === "image" ? "image_file" as const : "mbox_message" as const,
    availability:
      row.state === "quarantine" ? "quarantined" as const : "present" as const,
    provenance_label:
      row.state === "quarantine" ? row.display_name : row.source_label,
    raw_blob_sha256: "0".repeat(64),
  };
}

function toWireEvidence(row: Evidence): EvidenceSnapshotV1 {
  return {
    evidence_id: row.evidence_id,
    source: sourceFor(row),
    kind: row.kind === "image" ? "image" : "message_attachment",
    state: row.state === "unresolved" ? "unresolved" : "deferred",
    assigned_item_id: null,
    review_label: row.display_name,
  };
}

function toWireQuarantine(row: Evidence): QuarantineSnapshotV1 {
  return {
    quarantine_id: row.evidence_id,
    source: sourceFor(row),
    code: row.quarantine_reason ?? "unsupported",
    raw_blob_preserved: true,
    no_blob_reason: null,
  };
}

function deletionPage(
  className: DeletionDependencyClassV1,
  rows: Array<{ id: string; label: string }>,
  offset: number,
): DeletionPlanItemV1[] {
  return rows.slice(offset, offset + pageSize).map((row) => ({
    class: className,
    record_id: row.id,
    display_label: row.label,
    retained: className === "retained_shared_blobs",
  }));
}

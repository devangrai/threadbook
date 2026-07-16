import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  GetOutfitTryOnV1Request,
  GetOutfitTryOnV1Response,
  ListTryOnPortraitCandidatesV1Request,
  ListTryOnPortraitCandidatesV1Response,
  OpenAiRetentionDeclarationV1,
  PreviewTryOnV1Request,
  PreviewTryOnV1Response,
  SubmitTryOnV1Request,
  SubmitTryOnV1Response,
  TryOnGarmentSourceV1,
  TryOnJobV1,
  TryOnOutputV1,
  TryOnRetentionDisclosureV1,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type TryOnImageV1 = {
  mediaType: string;
  bytes: number[];
};

export type TryOnPortraitCandidateView = {
  sourceRevisionId: string;
  label: string;
  thumbnail: TryOnImageV1;
};

export type TryOnAssetDescriptorView = {
  ordinal: number;
  role: "portrait" | "garment";
  label: string;
  itemId: string | null;
  localReferenceId: string;
  transmittedFilename: string;
  canonicalSha256: string;
  mediaType: string;
  byteLength: number;
  width: number;
  height: number;
};

export type TryOnPreviewView = {
  approvalId: string;
  providerStatus: "ready" | "credential_unavailable" | "unavailable";
  provider: string;
  model: string;
  purpose: string;
  retentionSummary: string;
  assets: TryOnAssetDescriptorView[];
};

export type TryOnGarmentView = {
  ordinal: number;
  itemId: string;
  label: string;
  image: TryOnImageV1;
};

export type TryOnJobView = {
  jobId: string;
  outfitId: string;
  state: "queued" | "running" | "succeeded" | "failed";
  statusMessage: string;
  failureCode: string | null;
  retryable: boolean;
  output: TryOnImageV1 | null;
  garments: TryOnGarmentView[];
};

export type TryOnPortraitPageView = {
  candidates: TryOnPortraitCandidateView[];
  nextCursor: string | null;
};

export type TryOnBridge = {
  listPortraitCandidates: (
    cursor?: string | null,
    limit?: number,
  ) => Promise<TryOnPortraitPageView>;
  preview: (
    outfitId: string,
    portraitSourceRevisionId: string,
    credentialId: string,
    retention: OpenAiRetentionDeclarationV1,
    expectedOutfitRevision: number,
  ) => Promise<TryOnPreviewView>;
  submit: (approvalId: string) => Promise<TryOnJobView>;
  getOutfitTryOn: (outfitId: string) => Promise<TryOnJobView | null>;
};

export function createTryOnBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): TryOnBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async listPortraitCandidates(cursor = null, limit = 20) {
      const request: ListTryOnPortraitCandidatesV1Request = {
        ...envelope(),
        cursor,
        limit,
      };
      const response =
        await invokeCommand<ListTryOnPortraitCandidatesV1Response>(
          "list_try_on_portrait_candidates_v1",
          { request },
        );
      return normalizePortraitPage(response);
    },

    async preview(
      outfitId,
      portraitSourceRevisionId,
      credentialId,
      retention,
      expectedOutfitRevision,
    ) {
      const request: PreviewTryOnV1Request = {
        ...envelope(),
        outfit_id: outfitId,
        portrait_source_revision_id: portraitSourceRevisionId,
        credential_id: credentialId,
        retention,
        expected_outfit_revision: expectedOutfitRevision,
      };
      const response = await invokeCommand<PreviewTryOnV1Response>(
        "preview_try_on_v1",
        { request },
      );
      return normalizePreview(response);
    },

    async submit(approvalId) {
      const request: SubmitTryOnV1Request = {
        ...envelope(),
        approval_id: approvalId,
      };
      const response = await invokeCommand<SubmitTryOnV1Response>(
        "submit_try_on_v1",
        { request },
      );
      return normalizeJob(response.job, null, []);
    },

    async getOutfitTryOn(outfitId) {
      const request: GetOutfitTryOnV1Request = {
        ...envelope(),
        outfit_id: outfitId,
      };
      const response = await invokeCommand<GetOutfitTryOnV1Response>(
        "get_outfit_try_on_v1",
        { request },
      );
      return normalizeGetResponse(response);
    },
  };
}

export const tryOnBridge = createTryOnBridge(productionInvoke);

function normalizePortraitPage(
  response: ListTryOnPortraitCandidatesV1Response,
): TryOnPortraitPageView {
  return {
    candidates: response.candidates.map((candidate) => ({
      sourceRevisionId: candidate.source_revision_id,
      label: candidate.captured_at
        ? `Portrait from ${candidate.captured_at}`
        : "Analyzed portrait",
      thumbnail: {
        mediaType: candidate.media_type,
        bytes: candidate.thumbnail_bytes,
      },
    })),
    nextCursor: response.next_cursor,
  };
}

function normalizePreview(response: PreviewTryOnV1Response): TryOnPreviewView {
  return {
    approvalId: response.approval.approval_id,
    providerStatus: "ready",
    provider:
      response.disclosure.provider === "openai"
        ? "OpenAI"
        : response.disclosure.provider,
    model: response.disclosure.model,
    purpose: humanize(response.disclosure.purpose),
    retentionSummary: retentionSummary(response.disclosure.retention),
    assets: response.disclosure.assets.map((asset) => ({
      ordinal: asset.ordinal,
      role: asset.role,
      label:
        asset.role === "portrait"
          ? "Selected portrait"
          : `Garment ${asset.ordinal} (${asset.transmitted_filename})`,
      itemId: asset.item_id,
      localReferenceId:
        asset.portrait_source_revision_id ?? asset.item_id ?? "unavailable",
      transmittedFilename: asset.transmitted_filename,
      canonicalSha256: asset.canonical_sha256,
      mediaType: asset.media_type,
      byteLength: asset.byte_length,
      width: asset.width,
      height: asset.height,
    })),
  };
}

function normalizeGetResponse(
  response: GetOutfitTryOnV1Response,
): TryOnJobView | null {
  if (!response.latest_job) return null;
  return normalizeJob(
    response.latest_job,
    response.output,
    response.garment_sources,
  );
}

function normalizeJob(
  job: TryOnJobV1,
  output: TryOnOutputV1 | null,
  garments: TryOnGarmentSourceV1[],
): TryOnJobView {
  return {
    jobId: job.job_id,
    outfitId: job.outfit_id,
    state: job.state,
    statusMessage: statusMessage(job),
    failureCode: job.failure?.code ?? null,
    retryable: job.failure?.retryable ?? false,
    output: output ? normalizeImage(output) : null,
    garments: garments.map((garment) => ({
      ordinal: garment.ordinal,
      itemId: garment.item_id,
      label: garment.attributes.display_name,
      image: {
        mediaType: garment.media_type,
        bytes: garment.bytes,
      },
    })),
  };
}

function normalizeImage(image: {
  media_type: string;
  bytes: number[];
}): TryOnImageV1 {
  return {
    mediaType: image.media_type,
    bytes: image.bytes,
  };
}

function retentionSummary(
  retention: TryOnRetentionDisclosureV1,
): string {
  const applicationState = retention.images_api_has_application_state_retention
    ? "The images endpoint uses application-state retention."
    : "The images endpoint has no application-state retention.";
  const compatibility =
    retention.model_is_zdr_compatible &&
    retention.compatibility_is_not_project_enrollment
      ? "The model is ZDR-compatible; this does not mean this project uses ZDR."
      : "No Zero Data Retention status is claimed.";
  const safety =
    retention.csam_input_scanning_applies &&
    retention.flagged_inputs_may_be_retained_for_review
      ? "Inputs are scanned for CSAM and flagged inputs may be retained for review."
      : "Provider safety review terms apply.";
  return `${applicationState} Default abuse monitoring may retain content for up to ${retention.default_abuse_monitoring_max_days} days. ${compatibility} ${safety}`;
}

function statusMessage(job: TryOnJobV1): string {
  if (job.state === "queued") return "Visualization queued.";
  if (job.state === "running") {
    return "OpenAI is generating the visualization.";
  }
  if (job.state === "succeeded") return "Visualization ready.";
  return job.failure
    ? `Generation failed: ${humanize(job.failure.code)}.`
    : "Generation failed.";
}

function humanize(value: string): string {
  const normalized = value.replaceAll("_", " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

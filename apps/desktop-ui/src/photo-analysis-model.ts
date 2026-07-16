import type {
  PhotoObservationV1,
  PhotoSegmentationOutcomeCodeV1,
  ReadPhotoArtifactV1Response,
  RectV1,
  SegmentationUnavailableReasonV1,
} from "./generated/contracts";

export type RectangleDraft = {
  x: string;
  y: string;
  width: string;
  height: string;
};

export type VerifiedPhotoArtifact = {
  artifactId: string;
  mediaType: string;
  width: number;
  height: number;
  bytes: Uint8Array;
};

export function abbreviateHash(hash: string): string {
  return hash.length > 20
    ? `${hash.slice(0, 10)}...${hash.slice(-8)}`
    : hash;
}

export function rectangleDraft(
  rectangle: RectV1 | null,
  sourceWidth: number,
  sourceHeight: number,
): RectangleDraft {
  const value = rectangle ?? {
    x: 0,
    y: 0,
    width: sourceWidth,
    height: sourceHeight,
  };
  return {
    x: String(value.x),
    y: String(value.y),
    width: String(value.width),
    height: String(value.height),
  };
}

export function parseRectangleDraft(
  draft: RectangleDraft,
  sourceWidth: number,
  sourceHeight: number,
): { rectangle: RectV1 | null; error: string | null } {
  const values = [draft.x, draft.y, draft.width, draft.height].map(
    parseWholeNumber,
  );
  if (values.some((value) => value === null)) {
    return {
      rectangle: null,
      error: "Rectangle values must be whole numbers.",
    };
  }
  const [x, y, width, height] = values as [number, number, number, number];
  if (width < 1 || height < 1) {
    return {
      rectangle: null,
      error: "Rectangle width and height must be at least 1.",
    };
  }
  if (
    x < 0 ||
    y < 0 ||
    x + width > sourceWidth ||
    y + height > sourceHeight
  ) {
    return {
      rectangle: null,
      error: `Rectangle must fit within ${sourceWidth} by ${sourceHeight}.`,
    };
  }
  return { rectangle: { x, y, width, height }, error: null };
}

export async function verifyPhotoArtifact(
  response: ReadPhotoArtifactV1Response,
): Promise<VerifiedPhotoArtifact> {
  if (
    !Number.isInteger(response.width) ||
    !Number.isInteger(response.height) ||
    response.width < 1 ||
    response.height < 1
  ) {
    throw new Error("Photo preview dimensions are invalid.");
  }
  if (
    response.bytes.some(
      (value) => !Number.isInteger(value) || value < 0 || value > 255,
    )
  ) {
    throw new Error("Photo preview bytes are invalid.");
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("Photo preview verification is unavailable.");
  }

  const bytes = Uint8Array.from(response.bytes);
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(bytes).buffer,
  );
  const actual = [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  if (actual !== response.bytes_sha256.toLowerCase()) {
    throw new Error("Photo preview integrity check failed.");
  }

  return {
    artifactId: response.artifact_id,
    mediaType: response.media_type,
    width: response.width,
    height: response.height,
    bytes,
  };
}

export function observationOutcome(
  observation: PhotoObservationV1,
): string {
  const { artifact } = observation;
  if (artifact.segmentation_outcome === "unavailable") {
    return `Segmentation unavailable: ${unavailableReason(
      artifact.unavailable_reason,
    )}. ${fallbackLabel(artifact.kind)} retained.`;
  }
  return `${outcomeLabel(artifact.segmentation_outcome)}. ${fallbackLabel(
    artifact.kind,
  )} retained.`;
}

export function isPhotoConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "request_conflict"
  );
}

export function displayPhotoError(error: unknown): string {
  if (isPhotoConflict(error)) {
    return "This photo review changed. Latest results were reloaded and your rectangle is still here.";
  }
  if (
    error instanceof Error &&
    (error.message.startsWith("Photo preview") ||
      error.message.startsWith("Rectangle"))
  ) {
    return error.message;
  }
  return "The local photo operation could not be completed.";
}

export function appendUniqueObservations(
  current: readonly PhotoObservationV1[],
  incoming: readonly PhotoObservationV1[],
): PhotoObservationV1[] {
  const values = new Map(
    current.map((observation) => [observation.observation_id, observation]),
  );
  for (const observation of incoming) {
    values.set(observation.observation_id, observation);
  }
  return [...values.values()];
}

function parseWholeNumber(value: string): number | null {
  const normalized = value.trim();
  if (!/^\d+$/u.test(normalized)) return null;
  const number = Number(normalized);
  return Number.isSafeInteger(number) ? number : null;
}

function unavailableReason(
  reason: SegmentationUnavailableReasonV1 | null,
): string {
  if (reason === "reviewed_model_pack_absent") {
    return "reviewed model pack absent";
  }
  if (reason === "capability_disabled") return "capability disabled";
  if (reason === "resource_unavailable") return "local resource unavailable";
  return "reason unavailable";
}

function outcomeLabel(outcome: PhotoSegmentationOutcomeCodeV1): string {
  return outcome
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function fallbackLabel(kind: PhotoObservationV1["artifact"]["kind"]): string {
  return kind === "rectangle_source_crop"
    ? "Rectangular source crop"
    : "Source image reference";
}

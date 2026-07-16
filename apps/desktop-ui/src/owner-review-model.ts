import type {
  PhotoOwnerReviewStateV1,
  ReadPhotoOwnerPreviewV1Response,
} from "./generated/contracts";

export type VerifiedOwnerPreview = {
  ownerReviewId: string;
  previewId: string;
  mediaType: string;
  width: number;
  height: number;
  bytes: Uint8Array;
};

export async function verifyOwnerPreview(
  response: ReadPhotoOwnerPreviewV1Response,
): Promise<VerifiedOwnerPreview> {
  if (
    !Number.isInteger(response.width) ||
    !Number.isInteger(response.height) ||
    response.width < 1 ||
    response.height < 1
  ) {
    throw new Error("Owner preview dimensions are invalid.");
  }
  if (
    !Number.isSafeInteger(response.byte_length) ||
    response.byte_length !== response.bytes.length ||
    response.bytes.some(
      (value) => !Number.isInteger(value) || value < 0 || value > 255,
    )
  ) {
    throw new Error("Owner preview bytes are invalid.");
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("Owner preview verification is unavailable.");
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
    throw new Error("Owner preview integrity check failed.");
  }

  return {
    ownerReviewId: response.owner_review_id,
    previewId: response.preview_id,
    mediaType: response.media_type,
    width: response.width,
    height: response.height,
    bytes,
  };
}

export function isOwnerConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "request_conflict"
  );
}

export function displayOwnerError(error: unknown): string {
  if (isOwnerConflict(error)) {
    return "This owner review changed. Latest evidence was reloaded and your selection is still here.";
  }
  if (error instanceof Error && error.message.startsWith("Owner preview")) {
    return error.message;
  }
  return "The local owner review operation could not be completed.";
}

export function ownerReviewStateLabel(
  state: PhotoOwnerReviewStateV1,
): string {
  switch (state) {
    case "instances_available":
      return "People found";
    case "no_person_detected":
      return "No person found";
    case "retryable_failure":
      return "Needs retry";
    case "permanent_unavailable":
      return "Detection unavailable";
    case "overflow":
      return "Too many people";
  }
}

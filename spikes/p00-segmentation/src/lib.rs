pub mod candidate;
pub mod contract;
pub mod dataset;
pub mod fallback;
pub mod freeze;
pub mod metrics;
pub mod sandbox;
pub mod timing;

pub use contract::{
    validate_outcome, Cancellation, ComputePolicy, ContractError, Deadline,
    GarmentSegmentationProvider, InferenceMode, InferenceRequest, Mask, PixelBuffer,
    ProviderDescriptor, ProviderPreparation, Rect, RequestHandle, SegmentationOutcome,
    TargetPersonContext, CONTRACT_SCHEMA_VERSION, MAX_DEADLINE_MS, MAX_MASKS, MAX_PIXELS,
    MAX_PROVIDER_MASKS,
};

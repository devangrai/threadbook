use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

pub const CONTRACT_SCHEMA_VERSION: u32 = 1;
pub const MAX_GATEWAY_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_CALLBACK_CHUNK_BYTES: usize = 1024 * 1024;
pub const PHOTOS_NETWORK_REQUIRED_DOMAIN: &str = "PHPhotosErrorDomain";
pub const PHOTOS_NETWORK_REQUIRED_CODE: i64 = 3164;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationMode {
    PhotoLibrary,
    PickerOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationPolicy {
    OriginalPrimaryV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueAssetRef(String);

impl OpaqueAssetRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_token("asset_ref", &value, 128)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLocatorV1 {
    pub key_version: u32,
    pub lookup_hmac: String,
    pub ciphertext: String,
}

impl ProtectedLocatorV1 {
    fn validate(&self) -> Result<(), ContractError> {
        if self.key_version == 0 {
            return Err(ContractError::InvalidField("locator.key_version"));
        }
        validate_lower_hex("locator.lookup_hmac", &self.lookup_hmac, 64)?;
        validate_token("locator.ciphertext", &self.ciphertext, 1024)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSelectionV1 {
    pub asset_ref: OpaqueAssetRef,
    pub connector_generation: String,
    pub local_locator: ProtectedLocatorV1,
    pub cloud_locator: Option<ProtectedLocatorV1>,
}

impl AssetSelectionV1 {
    fn validate(&self, requires_connector_generation: bool) -> Result<(), ContractError> {
        if requires_connector_generation {
            validate_token("connector_generation", &self.connector_generation, 128)?;
        } else if !self.connector_generation.is_empty() {
            return Err(ContractError::InvalidField("picker_only_provenance"));
        }
        self.local_locator.validate()?;
        if let Some(locator) = &self.cloud_locator {
            locator.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartMaterializationV1 {
    pub schema_version: u32,
    pub client_request_id: String,
    pub mode: MaterializationMode,
    pub selection_limit: u16,
    pub representation_policy: RepresentationPolicy,
    pub assets: Vec<AssetSelectionV1>,
}

impl StartMaterializationV1 {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.is_empty() || bytes.len() > MAX_GATEWAY_MESSAGE_BYTES {
            return Err(ContractError::MessageSize);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| ContractError::MalformedMessage)?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion);
        }
        validate_token("client_request_id", &self.client_request_id, 128)?;
        if self.selection_limit == 0 || self.selection_limit > 100 {
            return Err(ContractError::InvalidField("selection_limit"));
        }
        if self.assets.is_empty()
            || self.assets.len() > usize::from(self.selection_limit)
            || self.assets.len() > 100
        {
            return Err(ContractError::InvalidField("assets"));
        }
        let requires_connector_generation = self.mode == MaterializationMode::PhotoLibrary;
        for asset in &self.assets {
            asset.validate(requires_connector_generation)?;
        }
        let mut refs = self
            .assets
            .iter()
            .map(|asset| asset.asset_ref.as_str())
            .collect::<Vec<_>>();
        refs.sort_unstable();
        if refs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ContractError::InvalidField("duplicate_asset_ref"));
        }
        Ok(())
    }

    pub fn envelope_hash(&self) -> Result<String, ContractError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| ContractError::MalformedMessage)?;
        Ok(hex_sha256(&encoded))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDescriptorV1 {
    pub schema_version: u32,
    pub resource_ref: String,
    pub uniform_type_identifier: String,
    pub pixel_width: u32,
    pub pixel_height: u32,
    pub frame_count: u16,
}

impl ResourceDescriptorV1 {
    pub fn validate(&self, limits: MaterializationLimits) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion);
        }
        validate_token("resource_ref", &self.resource_ref, 128)?;
        if !matches!(
            self.uniform_type_identifier.as_str(),
            "public.png" | "public.jpeg"
        ) {
            return Err(ContractError::UnsupportedResource);
        }
        let pixels = u64::from(self.pixel_width)
            .checked_mul(u64::from(self.pixel_height))
            .ok_or(ContractError::ImageBounds)?;
        if self.pixel_width == 0
            || self.pixel_height == 0
            || pixels > limits.max_pixels
            || self.frame_count != 1
        {
            return Err(ContractError::ImageBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    ResidencyProbe,
    CloudTransfer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRequestV1 {
    pub schema_version: u32,
    pub operation_id: String,
    pub asset_ref: OpaqueAssetRef,
    pub resource: ResourceDescriptorV1,
    pub request_generation: u64,
    pub kind: TransferKind,
    pub network_access_allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFailure {
    Authorization,
    SelectionIdentity,
    UnsupportedResource,
    NetworkRequired,
    Transfer,
    Cancellation,
    Progress,
    OutputIntegrity,
    ProvenanceIntegrity,
    NativeProtocol,
}

impl fmt::Display for GatewayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "photo gateway failure: {}", self.code())
    }
}

impl Error for GatewayFailure {}

impl GatewayFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::SelectionIdentity => "selection_identity",
            Self::UnsupportedResource => "unsupported_resource",
            Self::NetworkRequired => "network_required",
            Self::Transfer => "transfer",
            Self::Cancellation => "cancellation",
            Self::Progress => "progress",
            Self::OutputIntegrity => "output_integrity",
            Self::ProvenanceIntegrity => "provenance_integrity",
            Self::NativeProtocol => "native_protocol",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum GatewayEventV1 {
    Started {
        request_generation: u64,
    },
    Chunk {
        request_generation: u64,
        bytes: Vec<u8>,
    },
    Progress {
        request_generation: u64,
        fraction: f64,
    },
    Completed {
        request_generation: u64,
        result: Result<(), GatewayFailure>,
    },
}

impl GatewayEventV1 {
    pub fn generation(&self) -> u64 {
        match self {
            Self::Started { request_generation }
            | Self::Chunk {
                request_generation, ..
            }
            | Self::Progress {
                request_generation, ..
            }
            | Self::Completed {
                request_generation, ..
            } => *request_generation,
        }
    }
}

pub trait PhotoAssetGateway {
    fn select_resource(
        &mut self,
        asset: &OpaqueAssetRef,
    ) -> Result<ResourceDescriptorV1, GatewayFailure>;

    fn request(
        &mut self,
        request: &GatewayRequestV1,
        lifecycle: &dyn RequestRegistrationPort,
    ) -> Result<Vec<GatewayEventV1>, GatewayFailure>;

    fn cancellation_port(&self) -> Arc<dyn GatewayCancellationPort>;
}

pub trait GatewayCancellationPort: Send + Sync {
    fn cancel(&self, native_request_id: &str);
}

pub trait RequestRegistrationPort: Send + Sync {
    fn register(&self, native_request_id: &str) -> Result<CallbackDisposition, GatewayFailure>;
    fn cancel_operation(&self) -> Result<(), GatewayFailure>;
    fn accept_callback(&self, kind: CallbackKind) -> Result<CallbackDisposition, GatewayFailure>;
    fn complete(&self) -> Result<(), GatewayFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackKind {
    Started,
    Chunk,
    Progress,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackDisposition {
    Accepted,
    IgnoredStale,
    IgnoredCancelled,
    IgnoredAfterTerminal,
    CancelImmediately(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaterializationLimits {
    pub max_assets: usize,
    pub max_resource_bytes: u64,
    pub max_batch_bytes: u64,
    pub max_active_staging_bytes: u64,
    pub max_concurrent_requests: usize,
    pub max_pixels: u64,
    pub max_decode_allocation_bytes: u64,
    pub reserve_free_bytes: u64,
}

impl MaterializationLimits {
    pub const P00: Self = Self {
        max_assets: 100,
        max_resource_bytes: 512 * 1024 * 1024,
        max_batch_bytes: 5 * 1024 * 1024 * 1024,
        max_active_staging_bytes: 1024 * 1024 * 1024,
        max_concurrent_requests: 2,
        max_pixels: 200_000_000,
        max_decode_allocation_bytes: 800_000_000,
        reserve_free_bytes: 2 * 1024 * 1024 * 1024,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationClass {
    Local,
    Cloud,
    PickerImport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRef {
    pub operation_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationSnapshot {
    pub operation_id: String,
    pub state: OperationState,
    pub generation: u64,
    pub completed: usize,
    pub total: usize,
    pub terminal_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticClass {
    Authorization,
    SelectionIdentity,
    UnsupportedResource,
    NetworkRequired,
    Transfer,
    Cancellation,
    Progress,
    OutputIntegrity,
    ProvenanceIntegrity,
    NativeProtocol,
    Storage,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub class: DiagnosticClass,
    pub operation_phase: &'static str,
    pub completed_count: usize,
    pub total_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    MessageSize,
    MalformedMessage,
    SchemaVersion,
    InvalidField(&'static str),
    UnsupportedResource,
    ImageBounds,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MessageSize => "contract message size is invalid",
            Self::MalformedMessage => "contract message is malformed",
            Self::SchemaVersion => "contract schema version is unsupported",
            Self::InvalidField(_) => "contract field is invalid",
            Self::UnsupportedResource => "resource is unsupported",
            Self::ImageBounds => "image bounds are invalid",
        })
    }
}

impl Error for ContractError {}

fn validate_token(field: &'static str, value: &str, maximum: usize) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn validate_lower_hex(
    field: &'static str,
    value: &str,
    length: usize,
) -> Result<(), ContractError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

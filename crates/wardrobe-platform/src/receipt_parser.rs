use html5ever::tokenizer::states::{RawKind, ScriptData};
use html5ever::tokenizer::{
    BufferQueue, CharacterTokens, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult,
    Tokenizer, TokenizerOpts,
};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use url::{Host, Url};
use uuid::Uuid;
pub use wardrobe_core::ReceiptImageCandidateEligibilityV1;
use wardrobe_core::{
    FragmentCitationV1, ParsedReceiptEvidenceV1, ReceiptFragmentId, ReceiptFragmentKindV1,
    ReceiptFragmentMetadataV1, ReceiptFragmentV1, ReceiptImageCandidateId, ReceiptParseId,
    Sha256Digest, SourceId, Validate, MAX_RECEIPT_ATTRIBUTE_CHARS, MAX_RECEIPT_METADATA_CHARS,
};

pub const RECEIPT_PARSER_REVISION_V1: &str = "mail-parser-0.11.5/receipt-parser-v1";
pub const RECEIPT_SANITIZER_REVISION_V1: &str = "html5ever-0.38/receipt-sanitizer-v1";
pub const MAX_RAW_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_MIME_PARTS: usize = 200;
pub const MAX_MIME_DEPTH: usize = 16;
pub const MAX_HEADER_BYTES: usize = 256 * 1024;
pub const MAX_DECODED_PART_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_DECODED_TOTAL_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_FRAGMENT_BYTES: usize = 32 * 1024;
pub const MAX_FRAGMENT_TOTAL_BYTES: usize = 128 * 1024;
pub const MAX_CITATION_BYTES: usize = 512;
pub const MAX_RECEIPT_IMAGE_CANDIDATES: usize = 32;
pub const MAX_RECEIPT_IMAGE_URL_BYTES: usize = 2_048;
pub const MAX_RECEIPT_IMAGE_HOST_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptParseError {
    RawMessageTooLarge,
    MissingHeaderBoundary,
    HeaderLimit,
    MailParseFailed,
    MimePartLimit,
    MimeDepthLimit,
    DecodedPartLimit,
    DecodedTotalLimit,
    FragmentLimit,
    FragmentTotalLimit,
    HtmlTokenizeFailed,
    CitationNotFound,
    CitationEmpty,
    CitationTooLong,
    CitationOutOfRange,
    CitationUtf8Boundary,
    CitationHashMismatch,
    ForeignCitation,
    ContractInvalid,
}

impl fmt::Display for ReceiptParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RawMessageTooLarge => "raw receipt message exceeds the byte limit",
            Self::MissingHeaderBoundary => "receipt message has no valid header boundary",
            Self::HeaderLimit => "receipt MIME headers exceed the byte limit",
            Self::MailParseFailed => "receipt MIME parsing failed",
            Self::MimePartLimit => "receipt MIME part count exceeds the limit",
            Self::MimeDepthLimit => "receipt MIME nesting exceeds the limit",
            Self::DecodedPartLimit => "decoded receipt MIME part exceeds the byte limit",
            Self::DecodedTotalLimit => "decoded receipt MIME aggregate exceeds the byte limit",
            Self::FragmentLimit => "receipt fragment count exceeds the limit",
            Self::FragmentTotalLimit => "receipt fragment aggregate exceeds the byte limit",
            Self::HtmlTokenizeFailed => "receipt HTML tokenization failed",
            Self::CitationNotFound => "receipt citation quote was not found",
            Self::CitationEmpty => "receipt citation is empty",
            Self::CitationTooLong => "receipt citation exceeds the byte limit",
            Self::CitationOutOfRange => "receipt citation is outside its fragment",
            Self::CitationUtf8Boundary => "receipt citation is not on UTF-8 boundaries",
            Self::CitationHashMismatch => "receipt citation quote hash does not match",
            Self::ForeignCitation => "receipt citation references a foreign fragment",
            Self::ContractInvalid => "parsed receipt does not satisfy the core contract",
        })
    }
}

impl std::error::Error for ReceiptParseError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiptParserV1;

impl ReceiptParserV1 {
    pub const fn new() -> Self {
        Self
    }

    pub fn parse(
        &self,
        source_id: SourceId,
        raw_message: &[u8],
    ) -> Result<ParsedReceiptEvidenceV1, ReceiptParseError> {
        parse_receipt_v1(source_id, raw_message)
    }

    pub fn parse_bundle(
        &self,
        source_id: SourceId,
        raw_message: &[u8],
    ) -> Result<ParsedReceiptBundleV1, ReceiptParseError> {
        parse_receipt_bundle_v1(source_id, raw_message)
    }
}

pub fn parse_receipt_v1(
    source_id: SourceId,
    raw_message: &[u8],
) -> Result<ParsedReceiptEvidenceV1, ReceiptParseError> {
    Ok(parse_receipt_bundle_v1(source_id, raw_message)?.evidence)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptImageCandidateInputV1 {
    pub candidate_id: ReceiptImageCandidateId,
    pub source_id: SourceId,
    pub parse_id: ReceiptParseId,
    pub part_ordinal: u16,
    pub normalized_url: String,
    pub display_host: String,
    pub candidate_url_sha256: Sha256Digest,
    pub eligibility: ReceiptImageCandidateEligibilityV1,
    pub occurrence_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReceiptBundleV1 {
    pub evidence: ParsedReceiptEvidenceV1,
    pub image_candidates: Vec<ReceiptImageCandidateInputV1>,
    pub image_candidate_overflow: u16,
}

pub fn parse_receipt_bundle_v1(
    source_id: SourceId,
    raw_message: &[u8],
) -> Result<ParsedReceiptBundleV1, ReceiptParseError> {
    if raw_message.len() > MAX_RAW_MESSAGE_BYTES {
        return Err(ReceiptParseError::RawMessageTooLarge);
    }
    let root_header_end =
        header_end(raw_message).ok_or(ReceiptParseError::MissingHeaderBoundary)?;
    if root_header_end > MAX_HEADER_BYTES {
        return Err(ReceiptParseError::HeaderLimit);
    }

    let message = MessageParser::default()
        .parse(raw_message)
        .ok_or(ReceiptParseError::MailParseFailed)?;
    if message.parts.len() > MAX_MIME_PARTS {
        return Err(ReceiptParseError::MimePartLimit);
    }
    if message.parts.is_empty() {
        return Err(ReceiptParseError::MailParseFailed);
    }

    let mut aggregate_headers = 0_usize;
    for part in &message.parts {
        let header_bytes = part
            .offset_body
            .checked_sub(part.offset_header)
            .ok_or(ReceiptParseError::MailParseFailed)? as usize;
        aggregate_headers = aggregate_headers
            .checked_add(header_bytes)
            .ok_or(ReceiptParseError::HeaderLimit)?;
    }
    if aggregate_headers > MAX_HEADER_BYTES {
        return Err(ReceiptParseError::HeaderLimit);
    }
    validate_mime_depth(&message.parts, 0, 0)?;

    let raw_blob_sha256 = Sha256Digest::from_bytes(raw_message);
    let parse_id = stable_parse_id(
        "receipt-parse",
        &format!(
            "{source_id}:{}:{RECEIPT_PARSER_REVISION_V1}:{RECEIPT_SANITIZER_REVISION_V1}",
            raw_blob_sha256.as_str()
        ),
    );
    let mut fragments = Vec::<FragmentAssembly>::new();
    let mut decoded_total = 0_usize;
    let mut fragment_total = 0_usize;
    let mut image_candidates = Vec::<ReceiptImageCandidateInputV1>::new();
    let mut image_candidate_overflow = 0_u16;

    for (part_ordinal, part) in message.parts.iter().enumerate() {
        let decoded_bytes = part.contents().len();
        if decoded_bytes > MAX_DECODED_PART_BYTES {
            return Err(ReceiptParseError::DecodedPartLimit);
        }
        decoded_total = decoded_total
            .checked_add(decoded_bytes)
            .ok_or(ReceiptParseError::DecodedTotalLimit)?;
        if decoded_total > MAX_DECODED_TOTAL_BYTES {
            return Err(ReceiptParseError::DecodedTotalLimit);
        }

        let content_type = normalized_content_type(part);
        let disposition = part.content_disposition().and_then(|value| {
            let disposition = value.c_type.to_ascii_lowercase();
            is_bounded_metadata(&disposition, MAX_RECEIPT_METADATA_CHARS).then_some(disposition)
        });
        let filename = part.attachment_name().and_then(safe_filename);
        let content_id = part.content_id().and_then(safe_content_id);
        let is_attachment = disposition.as_deref() == Some("attachment") || filename.is_some();
        let part_ordinal =
            u16::try_from(part_ordinal).map_err(|_| ReceiptParseError::MimePartLimit)?;

        match &part.body {
            PartType::Text(text) if !is_attachment => {
                push_text_fragments(
                    source_id,
                    &raw_blob_sha256,
                    part_ordinal,
                    ReceiptFragmentKindV1::PlainText,
                    canonicalize_text(text),
                    &mut fragments,
                    &mut fragment_total,
                )?;
            }
            PartType::Html(html) if !is_attachment => {
                let SanitizedHtmlV1 {
                    text,
                    referenced_cids,
                    remote_image_sources,
                } = sanitize_html_v1(html)?;
                collect_image_candidates(
                    source_id,
                    parse_id,
                    part_ordinal,
                    remote_image_sources,
                    &mut image_candidates,
                    &mut image_candidate_overflow,
                );
                push_text_fragments(
                    source_id,
                    &raw_blob_sha256,
                    part_ordinal,
                    ReceiptFragmentKindV1::SanitizedHtml,
                    text,
                    &mut fragments,
                    &mut fragment_total,
                )?;
                for referenced_cid in referenced_cids {
                    let metadata = ReceiptFragmentMetadataV1 {
                        content_type: "text/html".to_owned(),
                        disposition: None,
                        safe_filename: None,
                        content_id: Some(referenced_cid.clone()),
                        decoded_length: None,
                        content_sha256: None,
                    };
                    let text = format!(
                        "content_type=text/html\ncontent_id={referenced_cid}\nrelation=referenced"
                    );
                    push_single_fragment(
                        source_id,
                        &raw_blob_sha256,
                        part_ordinal,
                        ReceiptFragmentKindV1::CidMetadata,
                        text,
                        Some(metadata),
                        &mut fragments,
                        &mut fragment_total,
                    )?;
                }
            }
            PartType::Multipart(_) => {}
            _ => {
                let (text, metadata) = attachment_metadata(
                    &content_type,
                    disposition.as_deref(),
                    filename.as_deref(),
                    content_id.as_deref(),
                    decoded_bytes,
                    part.contents(),
                );
                push_single_fragment(
                    source_id,
                    &raw_blob_sha256,
                    part_ordinal,
                    ReceiptFragmentKindV1::AttachmentMetadata,
                    text,
                    Some(metadata),
                    &mut fragments,
                    &mut fragment_total,
                )?;
            }
        }

        if let Some(content_id) = content_id {
            let (text, metadata) = cid_metadata(
                &content_type,
                disposition.as_deref(),
                filename.as_deref(),
                &content_id,
                decoded_bytes,
                part.contents(),
            );
            push_single_fragment(
                source_id,
                &raw_blob_sha256,
                part_ordinal,
                ReceiptFragmentKindV1::CidMetadata,
                text,
                Some(metadata),
                &mut fragments,
                &mut fragment_total,
            )?;
        }
    }

    if fragments.is_empty() {
        return Err(ReceiptParseError::FragmentLimit);
    }
    let fragments = fragments
        .into_iter()
        .enumerate()
        .map(|(ordinal, fragment)| ReceiptFragmentV1 {
            fragment_id: fragment.fragment_id,
            ordinal: u16::try_from(ordinal).expect("fragment count was bounded"),
            kind: fragment.kind,
            content_sha256: Sha256Digest::from_bytes(fragment.text.as_bytes()),
            text: fragment.text,
            metadata: fragment.metadata,
        })
        .collect();
    let mut parsed = ParsedReceiptEvidenceV1 {
        parse_id,
        source_id,
        raw_blob_sha256,
        parser_revision: RECEIPT_PARSER_REVISION_V1.to_owned(),
        sanitizer_revision: RECEIPT_SANITIZER_REVISION_V1.to_owned(),
        canonical_input_sha256: Sha256Digest::from_bytes(b"pending"),
        fragments,
    };
    parsed.canonical_input_sha256 = parsed.compute_canonical_input_sha256();
    parsed
        .validate()
        .map_err(|_| ReceiptParseError::ContractInvalid)?;
    Ok(ParsedReceiptBundleV1 {
        evidence: parsed,
        image_candidates,
        image_candidate_overflow,
    })
}

pub fn citation_for_quote_v1(
    fragment: &ReceiptFragmentV1,
    quote: &str,
) -> Result<FragmentCitationV1, ReceiptParseError> {
    if quote.is_empty() {
        return Err(ReceiptParseError::CitationEmpty);
    }
    if quote.len() > MAX_CITATION_BYTES {
        return Err(ReceiptParseError::CitationTooLong);
    }
    let byte_start = fragment
        .text
        .find(quote)
        .ok_or(ReceiptParseError::CitationNotFound)?;
    let byte_end = byte_start + quote.len();
    let byte_start =
        u32::try_from(byte_start).map_err(|_| ReceiptParseError::CitationOutOfRange)?;
    let byte_end = u32::try_from(byte_end).map_err(|_| ReceiptParseError::CitationOutOfRange)?;
    Ok(FragmentCitationV1 {
        fragment_id: fragment.fragment_id,
        byte_start,
        byte_end,
        quote_sha256: Sha256Digest::from_bytes(quote.as_bytes()),
    })
}

pub fn verify_citation_v1(
    parse: &ParsedReceiptEvidenceV1,
    citation: &FragmentCitationV1,
) -> Result<(), ReceiptParseError> {
    let fragment = parse
        .fragments
        .iter()
        .find(|fragment| fragment.fragment_id == citation.fragment_id)
        .ok_or(ReceiptParseError::ForeignCitation)?;
    let start = citation.byte_start as usize;
    let end = citation.byte_end as usize;
    if start == end {
        return Err(ReceiptParseError::CitationEmpty);
    }
    if start > end || end > fragment.text.len() {
        return Err(ReceiptParseError::CitationOutOfRange);
    }
    if end - start > MAX_CITATION_BYTES {
        return Err(ReceiptParseError::CitationTooLong);
    }
    if !fragment.text.is_char_boundary(start) || !fragment.text.is_char_boundary(end) {
        return Err(ReceiptParseError::CitationUtf8Boundary);
    }
    if citation.quote_sha256 != Sha256Digest::from_bytes(&fragment.text.as_bytes()[start..end]) {
        return Err(ReceiptParseError::CitationHashMismatch);
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub struct SanitizedHtmlV1 {
    pub text: String,
    pub referenced_cids: Vec<String>,
    remote_image_sources: Vec<String>,
}

pub fn sanitize_html_v1(html: &str) -> Result<SanitizedHtmlV1, ReceiptParseError> {
    let sink = SanitizerSink::default();
    let input = BufferQueue::default();
    input.push_back(html.into());
    let tokenizer = Tokenizer::new(
        sink,
        TokenizerOpts {
            exact_errors: false,
            ..TokenizerOpts::default()
        },
    );
    let _ = tokenizer.feed(&input);
    if !input.is_empty() {
        return Err(ReceiptParseError::HtmlTokenizeFailed);
    }
    tokenizer.end();
    tokenizer.sink.finish()
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|offset| offset + 2)
        })
}

fn validate_mime_depth(
    parts: &[mail_parser::MessagePart<'_>],
    part_id: usize,
    depth: usize,
) -> Result<(), ReceiptParseError> {
    if depth > MAX_MIME_DEPTH || part_id >= parts.len() {
        return Err(ReceiptParseError::MimeDepthLimit);
    }
    if let PartType::Multipart(children) = &parts[part_id].body {
        if children.len() > MAX_MIME_PARTS {
            return Err(ReceiptParseError::MimePartLimit);
        }
        for child in children {
            validate_mime_depth(parts, *child as usize, depth + 1)?;
        }
    }
    Ok(())
}

fn normalized_content_type(part: &mail_parser::MessagePart<'_>) -> String {
    let content_type = part
        .content_type()
        .map(|value| {
            format!(
                "{}/{}",
                value.c_type.to_ascii_lowercase(),
                value
                    .c_subtype
                    .as_deref()
                    .unwrap_or("octet-stream")
                    .to_ascii_lowercase()
            )
        })
        .unwrap_or_else(|| match part.body {
            PartType::Text(_) => "text/plain".to_owned(),
            PartType::Html(_) => "text/html".to_owned(),
            PartType::Multipart(_) => "multipart/mixed".to_owned(),
            _ => "application/octet-stream".to_owned(),
        });
    if is_bounded_metadata(&content_type, MAX_RECEIPT_ATTRIBUTE_CHARS) {
        content_type
    } else {
        "application/octet-stream".to_owned()
    }
}

fn safe_filename(value: &str) -> Option<String> {
    let basename = value.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let sanitized: String = basename
        .chars()
        .filter(|character| !character.is_control())
        .take(255)
        .collect();
    (!sanitized.is_empty() && sanitized != "." && sanitized != "..").then_some(sanitized)
}

fn safe_content_id(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('<').trim_end_matches('>');
    if !is_bounded_metadata(value, MAX_RECEIPT_METADATA_CHARS) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn is_bounded_metadata(value: &str, max_chars: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max_chars && !value.chars().any(char::is_control)
}

fn attachment_metadata(
    content_type: &str,
    disposition: Option<&str>,
    filename: Option<&str>,
    content_id: Option<&str>,
    decoded_length: usize,
    decoded_bytes: &[u8],
) -> (String, ReceiptFragmentMetadataV1) {
    let content_sha256 = Sha256Digest::from_bytes(decoded_bytes);
    let mut fields = vec![
        format!("content_type={content_type}"),
        format!("disposition={}", disposition.unwrap_or("unspecified")),
    ];
    if let Some(filename) = filename {
        fields.push(format!("filename={filename}"));
    }
    if let Some(content_id) = content_id {
        fields.push(format!("content_id={content_id}"));
    }
    fields.push(format!("decoded_length={decoded_length}"));
    fields.push(format!("content_sha256={}", content_sha256.as_str()));
    (
        fields.join("\n"),
        ReceiptFragmentMetadataV1 {
            content_type: content_type.to_owned(),
            disposition: disposition.map(ToOwned::to_owned),
            safe_filename: filename.map(ToOwned::to_owned),
            content_id: content_id.map(ToOwned::to_owned),
            decoded_length: Some(decoded_length as u64),
            content_sha256: Some(content_sha256),
        },
    )
}

fn cid_metadata(
    content_type: &str,
    disposition: Option<&str>,
    filename: Option<&str>,
    content_id: &str,
    decoded_length: usize,
    decoded_bytes: &[u8],
) -> (String, ReceiptFragmentMetadataV1) {
    let content_sha256 = Sha256Digest::from_bytes(decoded_bytes);
    let mut fields = vec![
        format!("content_type={content_type}"),
        format!("disposition={}", disposition.unwrap_or("unspecified")),
    ];
    if let Some(filename) = filename {
        fields.push(format!("filename={filename}"));
    }
    fields.push(format!("content_id={content_id}"));
    fields.push(format!("decoded_length={decoded_length}"));
    fields.push(format!("content_sha256={}", content_sha256.as_str()));
    (
        fields.join("\n"),
        ReceiptFragmentMetadataV1 {
            content_type: content_type.to_owned(),
            disposition: disposition.map(ToOwned::to_owned),
            safe_filename: filename.map(ToOwned::to_owned),
            content_id: Some(content_id.to_owned()),
            decoded_length: Some(decoded_length as u64),
            content_sha256: Some(content_sha256),
        },
    )
}

fn canonicalize_text(text: &str) -> String {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut output = String::with_capacity(text.len());
    let mut blank = true;
    for line in text.lines() {
        let line = normalize_inline_whitespace(line);
        if line.is_empty() {
            if !blank && !output.is_empty() {
                output.push('\n');
                blank = true;
            }
        } else {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&line);
            blank = false;
        }
    }
    output.trim().to_owned()
}

fn normalize_inline_whitespace(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !output.is_empty();
        } else {
            if pending_space {
                output.push(' ');
            }
            output.push(character);
            pending_space = false;
        }
    }
    output
}

fn push_text_fragments(
    source_id: SourceId,
    raw_blob_sha256: &Sha256Digest,
    part_ordinal: u16,
    kind: ReceiptFragmentKindV1,
    content: String,
    fragments: &mut Vec<FragmentAssembly>,
    fragment_total: &mut usize,
) -> Result<(), ReceiptParseError> {
    if content.is_empty() {
        return Ok(());
    }
    for (chunk_ordinal, chunk) in split_utf8_chunks(&content, MAX_FRAGMENT_BYTES)
        .into_iter()
        .enumerate()
    {
        push_fragment(
            source_id,
            raw_blob_sha256,
            part_ordinal,
            u16::try_from(chunk_ordinal).map_err(|_| ReceiptParseError::FragmentLimit)?,
            kind,
            chunk,
            None,
            fragments,
            fragment_total,
        )?;
    }
    Ok(())
}

fn push_single_fragment(
    source_id: SourceId,
    raw_blob_sha256: &Sha256Digest,
    part_ordinal: u16,
    kind: ReceiptFragmentKindV1,
    content: String,
    metadata: Option<ReceiptFragmentMetadataV1>,
    fragments: &mut Vec<FragmentAssembly>,
    fragment_total: &mut usize,
) -> Result<(), ReceiptParseError> {
    push_fragment(
        source_id,
        raw_blob_sha256,
        part_ordinal,
        0,
        kind,
        content,
        metadata,
        fragments,
        fragment_total,
    )
}

fn push_fragment(
    source_id: SourceId,
    raw_blob_sha256: &Sha256Digest,
    part_ordinal: u16,
    chunk_ordinal: u16,
    kind: ReceiptFragmentKindV1,
    content: String,
    metadata: Option<ReceiptFragmentMetadataV1>,
    fragments: &mut Vec<FragmentAssembly>,
    fragment_total: &mut usize,
) -> Result<(), ReceiptParseError> {
    if content.is_empty() {
        return Ok(());
    }
    if content.len() > MAX_FRAGMENT_BYTES {
        return Err(ReceiptParseError::FragmentLimit);
    }
    if fragments.len() >= MAX_MIME_PARTS {
        return Err(ReceiptParseError::FragmentLimit);
    }
    *fragment_total = fragment_total
        .checked_add(content.len())
        .ok_or(ReceiptParseError::FragmentTotalLimit)?;
    if *fragment_total > MAX_FRAGMENT_TOTAL_BYTES {
        return Err(ReceiptParseError::FragmentTotalLimit);
    }
    let content_sha256 = Sha256Digest::from_bytes(content.as_bytes());
    let fragment_id = stable_fragment_id(
        "receipt-fragment",
        &format!(
            "{source_id}:{}:{part_ordinal}:{chunk_ordinal}:{}:{}",
            raw_blob_sha256.as_str(),
            fragment_kind_name(kind),
            content_sha256.as_str()
        ),
    );
    fragments.push(FragmentAssembly {
        fragment_id,
        kind,
        text: content,
        metadata,
    });
    Ok(())
}

fn split_utf8_chunks(value: &str, limit: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let remaining = value.len() - start;
        let mut end = start + remaining.min(limit);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        if end < value.len() {
            if let Some(newline) = value[start..end].rfind('\n') {
                if newline > 0 {
                    end = start + newline;
                }
            }
        }
        if end == start {
            end = value[start..]
                .char_indices()
                .nth(1)
                .map(|(offset, _)| start + offset)
                .unwrap_or(value.len());
        }
        let chunk = value[start..end].trim().to_owned();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        start = end;
        while value[start..].starts_with('\n') {
            start += 1;
        }
    }
    chunks
}

#[derive(Debug)]
struct FragmentAssembly {
    fragment_id: ReceiptFragmentId,
    kind: ReceiptFragmentKindV1,
    text: String,
    metadata: Option<ReceiptFragmentMetadataV1>,
}

fn stable_uuid(namespace: &str, input: &str) -> Uuid {
    let digest = Sha256::digest(format!("{namespace}:{input}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn stable_parse_id(namespace: &str, input: &str) -> ReceiptParseId {
    ReceiptParseId::new(stable_uuid(namespace, input)).expect("stable UUID is non-nil")
}

fn stable_fragment_id(namespace: &str, input: &str) -> ReceiptFragmentId {
    ReceiptFragmentId::new(stable_uuid(namespace, input)).expect("stable UUID is non-nil")
}

const fn fragment_kind_name(kind: ReceiptFragmentKindV1) -> &'static str {
    match kind {
        ReceiptFragmentKindV1::PlainText => "plain_text",
        ReceiptFragmentKindV1::SanitizedHtml => "sanitized_html",
        ReceiptFragmentKindV1::AttachmentMetadata => "attachment_metadata",
        ReceiptFragmentKindV1::CidMetadata => "cid_metadata",
    }
}

#[derive(Default)]
struct SanitizerState {
    output: String,
    referenced_cids: BTreeSet<String>,
    suppressed: Vec<String>,
    remote_image_sources: Vec<String>,
    open_cells: usize,
    failed: bool,
}

#[derive(Default)]
struct SanitizerSink {
    state: RefCell<SanitizerState>,
}

impl SanitizerSink {
    fn finish(self) -> Result<SanitizedHtmlV1, ReceiptParseError> {
        let state = self.state.into_inner();
        if state.failed {
            return Err(ReceiptParseError::HtmlTokenizeFailed);
        }
        let text = canonicalize_structural_text(&state.output);
        if text.len() > MAX_FRAGMENT_TOTAL_BYTES {
            return Err(ReceiptParseError::FragmentTotalLimit);
        }
        Ok(SanitizedHtmlV1 {
            text,
            referenced_cids: state.referenced_cids.into_iter().collect(),
            remote_image_sources: state.remote_image_sources,
        })
    }
}

impl TokenSink for SanitizerSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        if state.failed {
            return TokenSinkResult::Continue;
        }
        match token {
            CharacterTokens(characters) if state.suppressed.is_empty() => {
                append_characters(&mut state.output, &characters);
            }
            TagToken(tag) => {
                let name = tag.name.to_string().to_ascii_lowercase();
                match tag.kind {
                    StartTag => {
                        let hidden = is_suppressed_element(&name)
                            || has_hidden_attribute(&tag.attrs)
                            || !state.suppressed.is_empty();
                        if hidden {
                            if !tag.self_closing && !is_void_element(&name) {
                                state.suppressed.push(name.clone());
                            }
                        } else {
                            if name == "img" {
                                for attribute in &tag.attrs {
                                    let attr_name =
                                        attribute.name.local.to_string().to_ascii_lowercase();
                                    if attr_name == "src" {
                                        if let Some(cid) = cid_reference(&attribute.value) {
                                            state.referenced_cids.insert(cid);
                                        } else if is_remote_http_source(&attribute.value) {
                                            state
                                                .remote_image_sources
                                                .push(attribute.value.to_string());
                                        }
                                    } else if attr_name == "alt" {
                                        let alt = normalize_inline_whitespace(&attribute.value);
                                        if !alt.is_empty() {
                                            append_boundary(&mut state.output, " ");
                                            state.output.push_str("[image: ");
                                            state.output.push_str(&alt);
                                            state.output.push(']');
                                        }
                                    }
                                }
                            }
                            structural_start(&name, &mut state);
                        }
                    }
                    EndTag => {
                        if !state.suppressed.is_empty() {
                            if let Some(index) =
                                state.suppressed.iter().rposition(|value| value == &name)
                            {
                                state.suppressed.truncate(index);
                            }
                        } else {
                            structural_end(&name, &mut state);
                        }
                    }
                }
                if matches!(name.as_str(), "script") && tag.kind == StartTag {
                    return TokenSinkResult::RawData(ScriptData);
                }
                if matches!(
                    name.as_str(),
                    "style" | "xmp" | "iframe" | "noembed" | "noframes"
                ) && tag.kind == StartTag
                {
                    return TokenSinkResult::RawData(RawKind::Rawtext);
                }
                if matches!(name.as_str(), "title" | "textarea") && tag.kind == StartTag {
                    return TokenSinkResult::RawData(RawKind::Rcdata);
                }
            }
            _ => {}
        }
        if state.output.len() > MAX_FRAGMENT_TOTAL_BYTES.saturating_mul(2) {
            state.failed = true;
        }
        TokenSinkResult::Continue
    }
}

fn is_suppressed_element(name: &str) -> bool {
    matches!(
        name,
        "script"
            | "style"
            | "form"
            | "input"
            | "button"
            | "select"
            | "option"
            | "textarea"
            | "iframe"
            | "object"
            | "embed"
            | "applet"
            | "canvas"
            | "svg"
            | "math"
            | "audio"
            | "video"
            | "source"
            | "track"
            | "template"
            | "noscript"
            | "head"
            | "title"
            | "meta"
            | "link"
            | "base"
            | "dialog"
    )
}

fn cid_reference(value: &str) -> Option<String> {
    let prefix = value.get(..4)?;
    prefix
        .eq_ignore_ascii_case("cid:")
        .then(|| &value[4..])
        .and_then(safe_content_id)
}

fn is_remote_http_source(value: &str) -> bool {
    Url::parse(value.trim())
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some())
}

fn collect_image_candidates(
    source_id: SourceId,
    parse_id: ReceiptParseId,
    part_ordinal: u16,
    sources: Vec<String>,
    candidates: &mut Vec<ReceiptImageCandidateInputV1>,
    overflow: &mut u16,
) {
    for source in sources {
        let Some((normalized_url, display_host, eligibility)) = normalize_image_candidate(&source)
        else {
            *overflow = overflow.saturating_add(1);
            continue;
        };
        let candidate_url_sha256 = Sha256Digest::from_bytes(normalized_url.as_bytes());
        let candidate_id = ReceiptImageCandidateId::new(stable_uuid(
            "receipt-image-candidate",
            &format!(
                "{parse_id}:{part_ordinal}:{}",
                candidate_url_sha256.as_str()
            ),
        ))
        .expect("stable UUID is non-nil");
        if let Some(existing) = candidates
            .iter_mut()
            .find(|candidate| candidate.candidate_id == candidate_id)
        {
            existing.occurrence_count = existing.occurrence_count.saturating_add(1);
            continue;
        }
        if candidates.len() >= MAX_RECEIPT_IMAGE_CANDIDATES {
            *overflow = overflow.saturating_add(1);
            continue;
        }
        candidates.push(ReceiptImageCandidateInputV1 {
            candidate_id,
            source_id,
            parse_id,
            part_ordinal,
            normalized_url,
            display_host,
            candidate_url_sha256,
            eligibility,
            occurrence_count: 1,
        });
    }
}

fn normalize_image_candidate(
    source: &str,
) -> Option<(String, String, ReceiptImageCandidateEligibilityV1)> {
    let source = source.trim();
    if source.len() > MAX_RECEIPT_IMAGE_URL_BYTES {
        return None;
    }
    let mut url = Url::parse(source).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    let host = url.host()?;
    let (display_host, is_dns_name) = match host {
        Host::Domain(domain) => (
            domain.to_ascii_lowercase().trim_end_matches('.').to_owned(),
            true,
        ),
        Host::Ipv4(address) => (address.to_string(), false),
        Host::Ipv6(address) => (address.to_string(), false),
    };
    if display_host.is_empty()
        || display_host.len() > MAX_RECEIPT_IMAGE_HOST_BYTES
        || !display_host.is_ascii()
    {
        return None;
    }
    if is_dns_name {
        url.set_host(Some(&display_host)).ok()?;
    }
    let effective_port = url.port_or_known_default()?;
    let port_is_allowed = url.port().is_none_or(|port| port == 443);
    let eligible = url.scheme() == "https"
        && is_dns_name
        && url.username().is_empty()
        && url.password().is_none()
        && effective_port == 443
        && port_is_allowed;
    let host_for_url = match url.host()? {
        Host::Ipv6(address) => format!("[{address}]"),
        _ => display_host.clone(),
    };
    let mut normalized_url = format!("{}://", url.scheme());
    if !url.username().is_empty() || url.password().is_some() {
        normalized_url.push_str(url.username());
        if let Some(password) = url.password() {
            normalized_url.push(':');
            normalized_url.push_str(password);
        }
        normalized_url.push('@');
    }
    normalized_url.push_str(&host_for_url);
    normalized_url.push(':');
    normalized_url.push_str(&effective_port.to_string());
    normalized_url.push_str(url.path());
    if let Some(query) = url.query() {
        normalized_url.push('?');
        normalized_url.push_str(query);
    }
    if normalized_url.len() > MAX_RECEIPT_IMAGE_URL_BYTES {
        return None;
    }
    Some((
        normalized_url,
        display_host,
        if eligible {
            ReceiptImageCandidateEligibilityV1::Eligible
        } else {
            ReceiptImageCandidateEligibilityV1::Blocked
        },
    ))
}

fn is_void_element(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn has_hidden_attribute(attributes: &[html5ever::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let name = attribute.name.local.to_string().to_ascii_lowercase();
        let value = attribute.value.to_string().to_ascii_lowercase();
        name == "hidden"
            || (name == "aria-hidden" && value.trim() == "true")
            || (name == "style"
                && value.split(';').any(|declaration| {
                    let compact: String = declaration
                        .chars()
                        .filter(|character| !character.is_whitespace())
                        .collect();
                    compact.starts_with("display:none")
                        || compact.starts_with("visibility:hidden")
                        || compact.starts_with("content-visibility:hidden")
                }))
    })
}

fn structural_start(name: &str, state: &mut SanitizerState) {
    match name {
        "br" | "hr" | "p" | "div" | "section" | "article" | "header" | "footer" | "aside"
        | "main" | "nav" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" | "pre"
        | "address" | "ul" | "ol" | "dl" | "dt" | "dd" | "tr" | "table" => {
            append_boundary(&mut state.output, "\n");
        }
        "li" => {
            append_boundary(&mut state.output, "\n");
            state.output.push_str("- ");
        }
        "td" | "th" => {
            if state.open_cells > 0 {
                append_boundary(&mut state.output, " | ");
            }
            state.open_cells += 1;
        }
        _ => {}
    }
}

fn structural_end(name: &str, state: &mut SanitizerState) {
    match name {
        "p" | "div" | "section" | "article" | "header" | "footer" | "aside" | "main" | "nav"
        | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" | "pre" | "address" | "li"
        | "ul" | "ol" | "dl" | "dt" | "dd" | "tr" | "table" => {
            append_boundary(&mut state.output, "\n");
            if name == "tr" {
                state.open_cells = 0;
            }
        }
        _ => {}
    }
}

fn append_characters(output: &mut String, characters: &str) {
    let normalized = normalize_inline_whitespace(characters);
    if normalized.is_empty() {
        if !output.is_empty() && !output.ends_with([' ', '\n']) {
            output.push(' ');
        }
        return;
    }
    if !output.is_empty()
        && !output.ends_with([' ', '\n', '|', '-'])
        && !normalized.starts_with([',', '.', ':', ';', '!', '?', ')', ']', '}'])
    {
        output.push(' ');
    }
    output.push_str(&normalized);
}

fn append_boundary(output: &mut String, boundary: &str) {
    if output.is_empty() {
        return;
    }
    if boundary == "\n" {
        while output.ends_with(' ') {
            output.pop();
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
    } else if !output.ends_with([' ', '\n']) {
        output.push_str(boundary);
    }
}

fn canonicalize_structural_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for line in value.lines() {
        let mut line = normalize_inline_whitespace(line);
        while line.ends_with('|') || line.ends_with('-') {
            line.pop();
            line = line.trim_end().to_owned();
        }
        if !line.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&line);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardrobe_core::Validate;

    fn source_id() -> SourceId {
        SourceId::new(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()).unwrap()
    }

    #[test]
    fn sanitizer_removes_active_and_hidden_content_but_preserves_visible_data() {
        let html = r#"
            <body onload="steal()">
              <script>secret()</script><style>.x { color: red }</style>
              <form>hidden form</form><input value="hidden input">
              <p hidden>hidden attribute</p>
              <p style="display: none">hidden style</p>
              <p>MODEL: keep this as data.</p>
              <a href="https://attacker.invalid">Visible link text</a>
              <img src="cid:item@example.invalid" alt="Visible alt">
              <img src="https://attacker.invalid/pixel">
            </body>
        "#;
        let sanitized = sanitize_html_v1(html).unwrap();
        assert!(!sanitized.text.contains("secret"));
        assert!(!sanitized.text.contains("hidden"));
        assert!(!sanitized.text.contains("https://"));
        assert!(sanitized.text.contains("MODEL: keep this as data."));
        assert!(sanitized.text.contains("Visible link text"));
        assert!(sanitized.text.contains("[image: Visible alt]"));
        assert_eq!(sanitized.referenced_cids, ["item@example.invalid"]);
    }

    #[test]
    fn sanitizer_normalizes_table_and_list_structure() {
        let html = "<table><tr><th>Event</th><th>Item</th></tr>\
                    <tr><td>Purchase</td><td>Caf\u{00e9} Tee</td></tr></table>\
                    <ul><li>one</li><li>two</li></ul>";
        let sanitized = sanitize_html_v1(html).unwrap();
        assert_eq!(
            sanitized.text,
            "Event | Item\nPurchase | Caf\u{00e9} Tee\n- one\n- two"
        );
    }

    #[test]
    fn parser_is_stable_and_attachment_bytes_do_not_enter_fragments() {
        let eml = b"From: a@example.invalid\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=x\r\n\r\n\
            --x\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
            Merchant: Example\r\nPurchase | Shirt | Qty 1\r\n\
            --x\r\nContent-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=../../unsafe.bin\r\n\
            Content-Transfer-Encoding: base64\r\n\r\n\
            U0VDUkVUX0JZVEVT\r\n--x--\r\n";
        let first = parse_receipt_v1(source_id(), eml).unwrap();
        let second = parse_receipt_v1(source_id(), eml).unwrap();
        assert_eq!(first, second);
        first.validate().unwrap();
        assert!(first
            .fragments
            .iter()
            .any(|fragment| fragment.kind == ReceiptFragmentKindV1::AttachmentMetadata));
        assert!(first
            .fragments
            .iter()
            .all(|fragment| !fragment.text.contains("SECRET_BYTES")));
        assert!(first.fragments.iter().any(|fragment| {
            fragment.kind == ReceiptFragmentKindV1::AttachmentMetadata
                && fragment.text.contains("filename=unsafe.bin")
        }));
    }

    #[test]
    fn citations_use_exact_utf8_byte_spans_and_hashes() {
        let eml = "From: a@example.invalid\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
                   Purchase | Caf\u{00e9} Tee | Qty 1\r\n";
        let parse = parse_receipt_v1(source_id(), eml.as_bytes()).unwrap();
        let fragment = &parse.fragments[0];
        let citation = citation_for_quote_v1(&fragment, "Caf\u{00e9} Tee").unwrap();
        assert_eq!(
            &fragment.text.as_bytes()[citation.byte_start as usize..citation.byte_end as usize],
            "Caf\u{00e9} Tee".as_bytes()
        );
        verify_citation_v1(&parse, &citation).unwrap();

        let mut invalid = citation;
        invalid.byte_start += 4;
        assert_eq!(
            verify_citation_v1(&parse, &invalid),
            Err(ReceiptParseError::CitationUtf8Boundary)
        );
    }

    #[test]
    fn parser_enforces_raw_header_and_fragment_bounds() {
        assert_eq!(
            parse_receipt_v1(source_id(), &vec![b'a'; MAX_RAW_MESSAGE_BYTES + 1]),
            Err(ReceiptParseError::RawMessageTooLarge)
        );

        let mut headers = b"Subject: ".to_vec();
        headers.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 1));
        headers.extend_from_slice(b"\r\n\r\nbody");
        assert_eq!(
            parse_receipt_v1(source_id(), &headers),
            Err(ReceiptParseError::HeaderLimit)
        );

        let bounded_body = "a".repeat(MAX_FRAGMENT_BYTES + 100);
        let bounded_message =
            format!("From: a@example.invalid\r\nContent-Type: text/plain\r\n\r\n{bounded_body}");
        let bounded = parse_receipt_v1(source_id(), bounded_message.as_bytes()).unwrap();
        assert_eq!(bounded.fragments.len(), 2);
        assert!(bounded
            .fragments
            .iter()
            .all(|fragment| fragment.text.len() <= MAX_FRAGMENT_BYTES));

        let oversized_body = "a".repeat(MAX_FRAGMENT_TOTAL_BYTES + 1);
        let oversized_message =
            format!("From: a@example.invalid\r\nContent-Type: text/plain\r\n\r\n{oversized_body}");
        assert_eq!(
            parse_receipt_v1(source_id(), oversized_message.as_bytes()),
            Err(ReceiptParseError::FragmentTotalLimit)
        );
        assert_eq!(
            citation_for_quote_v1(&bounded.fragments[0], &"a".repeat(MAX_CITATION_BYTES + 1)),
            Err(ReceiptParseError::CitationTooLong)
        );
    }
}

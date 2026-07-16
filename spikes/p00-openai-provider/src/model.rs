use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceString {
    pub value: Option<String>,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInteger {
    pub value: Option<u64>,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GarmentLineObservation {
    pub description: EvidenceString,
    pub brand: EvidenceString,
    pub category: EvidenceString,
    pub color: EvidenceString,
    pub size: EvidenceString,
    pub quantity: EvidenceInteger,
    pub unit_price_minor: EvidenceInteger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptObservationV1 {
    pub merchant: EvidenceString,
    pub purchase_date: EvidenceString,
    pub currency: EvidenceString,
    pub line_items: Vec<GarmentLineObservation>,
}

pub fn receipt_observation_schema() -> Value {
    let source_refs = json!({
        "type": "array",
        "items": {"type": "string", "minLength": 1, "maxLength": 128},
        "maxItems": 8
    });
    let evidence_string = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["value", "source_refs"],
        "properties": {
            "value": {"type": ["string", "null"], "maxLength": 512},
            "source_refs": source_refs
        }
    });
    let evidence_integer = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["value", "source_refs"],
        "properties": {
            "value": {"type": ["integer", "null"], "minimum": 0, "maximum": 100000000},
            "source_refs": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 128},
                "maxItems": 8
            }
        }
    });
    let line = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "description", "brand", "category", "color", "size", "quantity",
            "unit_price_minor"
        ],
        "properties": {
            "description": evidence_string,
            "brand": evidence_string,
            "category": evidence_string,
            "color": evidence_string,
            "size": evidence_string,
            "quantity": evidence_integer,
            "unit_price_minor": evidence_integer
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["merchant", "purchase_date", "currency", "line_items"],
        "properties": {
            "merchant": evidence_string,
            "purchase_date": evidence_string,
            "currency": evidence_string,
            "line_items": {
                "type": "array",
                "items": line,
                "maxItems": 100
            }
        }
    })
}

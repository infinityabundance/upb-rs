//! Oracle protocol v1 types (see tools/oracle/PROTOCOL.md).

use serde::{Deserialize, Serialize};

/// Primitive wire-reading operations exposed by the oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveOp {
    ReadVarint,
    ReadTag,
    ReadSize,
    ReadFixed32,
    ReadFixed64,
    SkipVarint,
}

impl PrimitiveOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrimitiveOp::ReadVarint => "read_varint",
            PrimitiveOp::ReadTag => "read_tag",
            PrimitiveOp::ReadSize => "read_size",
            PrimitiveOp::ReadFixed32 => "read_fixed32",
            PrimitiveOp::ReadFixed64 => "read_fixed64",
            PrimitiveOp::SkipVarint => "skip_varint",
        }
    }
}

/// A request sent to the oracle.
#[derive(Debug, Clone, Serialize)]
pub struct OracleRequest {
    pub v: u32,
    pub id: u64,
    pub op: String,
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u64>,
}

impl OracleRequest {
    pub fn primitive(id: u64, op: PrimitiveOp, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: op.as_str().to_string(),
            hex: hex_encode(payload),
            tag: None,
        }
    }

    pub fn skip_value(id: u64, tag: u32, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "skip_value".to_string(),
            hex: hex_encode(payload),
            tag: Some(tag as u64),
        }
    }

    pub fn skip_group(id: u64, tag: u32, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "skip_group".to_string(),
            hex: hex_encode(payload),
            tag: Some(tag as u64),
        }
    }
}

/// The response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Ok,
    Eof,
    Error,
}

/// A response from the oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResponse {
    pub v: u32,
    pub id: u64,
    pub status: ResponseStatus,
    /// Present when status == ok for value-producing ops; always a decimal
    /// string so u64 precision is preserved.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub consumed: Option<i64>,
    #[serde(default)]
    pub bounded: Option<bool>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub echo: Option<String>,
}

impl OracleResponse {
    pub fn value_u64(&self) -> Option<u64> {
        self.value.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Hex encoding used by the protocol (lowercase, even-length).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_shape() {
        let r = OracleRequest::primitive(7, PrimitiveOp::ReadVarint, &[0xFF, 0x80, 0x01]);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"op\":\"read_varint\""));
        assert!(json.contains("\"hex\":\"ff8001\""));
        assert!(json.contains("\"id\":7"));
        assert!(json.contains("\"v\":1"));
    }

    #[test]
    fn hex_encode_pads() {
        assert_eq!(hex_encode(&[0x0F]), "0f");
        assert_eq!(hex_encode(&[]), "");
    }
}

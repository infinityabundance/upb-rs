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

/// Arena configuration for the arena_* ops (mirrors the oracle's
/// parse_arena_cfg).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArenaCfg {
    pub initial_block: u64,
    pub alloc: bool,
    pub max_block_size: u64,
    pub fail_after_bytes: u64,
}

impl ArenaCfg {
    pub fn new() -> ArenaCfg {
        ArenaCfg {
            initial_block: 0,
            alloc: true,
            max_block_size: 0,
            fail_after_bytes: 0,
        }
    }
}

impl Default for ArenaCfg {
    fn default() -> ArenaCfg {
        ArenaCfg::new()
    }
}

/// One arena op: k is malloc|realloc|shrink|tryextend|message|strdup|cleanup.
/// `ref` is the op index for realloc/shrink/tryextend and the cleanup id for
/// cleanup; `hex` carries the strdup payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArenaOp {
    pub k: String,
    pub size: u64,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

impl ArenaOp {
    pub fn malloc(size: u64) -> ArenaOp {
        ArenaOp {
            k: "malloc".into(),
            size,
            r#ref: None,
            hex: None,
        }
    }
    pub fn realloc(r#ref: usize, size: u64) -> ArenaOp {
        ArenaOp {
            k: "realloc".into(),
            size,
            r#ref: Some(r#ref as u64),
            hex: None,
        }
    }
    pub fn shrink(r#ref: usize, size: u64) -> ArenaOp {
        ArenaOp {
            k: "shrink".into(),
            size,
            r#ref: Some(r#ref as u64),
            hex: None,
        }
    }
    pub fn tryextend(r#ref: usize, size: u64) -> ArenaOp {
        ArenaOp {
            k: "tryextend".into(),
            size,
            r#ref: Some(r#ref as u64),
            hex: None,
        }
    }
    pub fn message(table_size: u64) -> ArenaOp {
        ArenaOp {
            k: "message".into(),
            size: table_size,
            r#ref: None,
            hex: None,
        }
    }
    pub fn strdup(size: u64, hex: &str) -> ArenaOp {
        ArenaOp {
            k: "strdup".into(),
            size,
            r#ref: None,
            hex: Some(hex.into()),
        }
    }
    pub fn cleanup(id: u64) -> ArenaOp {
        ArenaOp {
            k: "cleanup".into(),
            size: 0,
            r#ref: Some(id),
            hex: None,
        }
    }
}

/// One generic collection op (array_trace / map_trace): k is
/// new|append|set|resize|get|insert|delete|iterate. Mirrors the oracle's
/// `GenOp` (tools/oracle/src/oracle.c:1445-1468); absent fields parse as 0
/// upstream (and `ref` as -1), so the DUT skips Nones.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GenOp {
    pub k: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<u64>,
    #[serde(rename = "key_type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<u64>,
    #[serde(rename = "val_type", skip_serializing_if = "Option::is_none")]
    pub val_type: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

impl GenOp {
    fn base() -> GenOp {
        GenOp {
            k: String::new(),
            size: None,
            r#ref: None,
            index: None,
            r#type: None,
            key_type: None,
            val_type: None,
            hex: None,
        }
    }
    /// array `new` op: the element `upb_CType` (the oracle derives the
    /// element-size lg2 from it).
    pub fn new_type(r#type: u64) -> GenOp {
        GenOp {
            r#type: Some(r#type),
            ..GenOp::base()
        }
    }
    /// map `new` op: the key/value `upb_CType`s.
    pub fn new_keyval(key_type: u64, val_type: u64) -> GenOp {
        GenOp {
            key_type: Some(key_type),
            val_type: Some(val_type),
            ..GenOp::base()
        }
    }
    /// append/insert/get/delete payload (insert uses `keyhex|valhex`).
    pub fn new_hex(hex: &str) -> GenOp {
        GenOp {
            hex: Some(hex.into()),
            ..GenOp::base()
        }
    }
    /// A bare reference (iterate).
    pub fn new_ref(r#ref: usize) -> GenOp {
        GenOp {
            r#ref: Some(r#ref as u64),
            ..GenOp::base()
        }
    }
    pub fn new_ref_index(r#ref: usize, index: u64) -> GenOp {
        GenOp {
            r#ref: Some(r#ref as u64),
            index: Some(index),
            ..GenOp::base()
        }
    }
    pub fn new_ref_hex(r#ref: usize, hex: &str) -> GenOp {
        GenOp {
            r#ref: Some(r#ref as u64),
            hex: Some(hex.into()),
            ..GenOp::base()
        }
    }
    pub fn new_ref_size(r#ref: usize, size: u64) -> GenOp {
        GenOp {
            r#ref: Some(r#ref as u64),
            size: Some(size),
            ..GenOp::base()
        }
    }
    pub fn new_ref_index_hex(r#ref: usize, index: u64, hex: &str) -> GenOp {
        GenOp {
            r#ref: Some(r#ref as u64),
            index: Some(index),
            hex: Some(hex.into()),
            ..GenOp::base()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md: Option<String>,
    /// decode_submsg: the pool descriptors (hex), main first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mds: Option<Vec<String>>,
    /// decode_submsg: per-table sub-slot -> table index (slot order = field
    /// order).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Vec<u64>>>,
    /// arena_trace: the arena configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arena: Option<ArenaCfg>,
    /// arena_trace: the op script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<Vec<ArenaOp>>,
    /// array_trace / map_trace: the generic op script. Serialized as "ops"
    /// (the oracle parses the same key for both); exactly one of `ops` and
    /// `gen_ops` is ever set per request.
    #[serde(rename = "ops", skip_serializing_if = "Option::is_none")]
    pub gen_ops: Option<Vec<GenOp>>,
    /// arena_fuse: side-a configuration and script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<ArenaCfg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a_ops: Option<Vec<ArenaOp>>,
    /// arena_fuse: side-b configuration and script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b: Option<ArenaCfg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b_ops: Option<Vec<ArenaOp>>,
    /// arena_fuse: post-fuse script (runs on b).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_ops: Option<Vec<ArenaOp>>,
    /// arena_trace: free the arena at the end and report cleanups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free: Option<bool>,
}

impl OracleRequest {
    pub fn primitive(id: u64, op: PrimitiveOp, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: op.as_str().to_string(),
            hex: hex_encode(payload),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn skip_value(id: u64, tag: u32, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "skip_value".to_string(),
            hex: hex_encode(payload),
            tag: Some(tag as u64),
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn skip_group(id: u64, tag: u32, payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "skip_group".to_string(),
            hex: hex_encode(payload),
            tag: Some(tag as u64),
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn decode_empty(id: u64, payload: &[u8], depth: u32) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "decode_empty".to_string(),
            hex: hex_encode(payload),
            tag: None,
            depth: Some(depth as u64),
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn decode_known(id: u64, md: &[u8], payload: &[u8]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "decode_known".to_string(),
            hex: hex_encode(payload),
            tag: None,
            depth: None,
            md: Some(hex_encode(md)),
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn decode_submsg(
        id: u64,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        payload: &[u8],
        depth: u32,
    ) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "decode_submsg".to_string(),
            hex: hex_encode(payload),
            tag: None,
            depth: Some(depth as u64),
            md: None,
            mds: Some(mds.iter().map(|m| hex_encode(m)).collect()),
            links: Some(links.to_vec()),
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn arena_info(id: u64) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "arena_info".to_string(),
            hex: String::new(),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        }
    }

    pub fn arena_trace(
        id: u64,
        arena: ArenaCfg,
        ops: &[ArenaOp],
        free_at_end: bool,
    ) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "arena_trace".to_string(),
            hex: String::new(),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: Some(arena),
            ops: Some(ops.to_vec()),
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: free_at_end.then_some(true),
        }
    }

    pub fn arena_fuse(
        id: u64,
        cfg_a: ArenaCfg,
        cfg_b: ArenaCfg,
        ops_a: &[ArenaOp],
        ops_b: &[ArenaOp],
        ops_post: &[ArenaOp],
    ) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: "arena_fuse".to_string(),
            hex: String::new(),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: Some(cfg_a),
            a_ops: Some(ops_a.to_vec()),
            b: Some(cfg_b),
            b_ops: Some(ops_b.to_vec()),
            post_ops: Some(ops_post.to_vec()),
            free: None,
        }
    }

    /// array_trace / map_trace: a generic op script under an arena config.
    pub fn gen_trace(id: u64, op: &str, arena: ArenaCfg, ops: &[GenOp]) -> OracleRequest {
        OracleRequest {
            v: 1,
            id,
            op: op.to_string(),
            hex: String::new(),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            arena: Some(arena),
            ops: None,
            gen_ops: Some(ops.to_vec()),
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
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
    /// decode_empty: the re-encoded bytes on success.
    #[serde(default)]
    pub hex_out: Option<String>,
    /// mini_table_inspect: the normalized mini table rendering on success.
    #[serde(default)]
    pub mini_table: Option<serde_json::Value>,
    /// mini_table_inspect error: the upstream error message.
    #[serde(default)]
    pub msg: Option<String>,
    /// decode_known: the normalized message dump on success.
    #[serde(default)]
    pub dump: Option<serde_json::Value>,
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

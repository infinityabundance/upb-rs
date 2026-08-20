//! Process client for the oracle server.
//!
//! Spawns `tools/oracle/build/oracle` and performs a versioned JSONL
//! request/response exchange over pipes. Every request receives exactly one
//! response, paired by `id`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::protocol::{OracleRequest, OracleResponse};
use serde::Deserialize;

#[derive(Debug)]
pub enum OracleError {
    Spawn(String),
    Write(String),
    Read(String),
    Protocol(String),
    Unpaired { expected: u64, got: u64 },
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleError::Spawn(s) => write!(f, "failed to spawn oracle: {s}"),
            OracleError::Write(s) => write!(f, "failed to write to oracle: {s}"),
            OracleError::Read(s) => write!(f, "failed to read from oracle: {s}"),
            OracleError::Protocol(s) => write!(f, "oracle protocol error: {s}"),
            OracleError::Unpaired { expected, got } => {
                write!(
                    f,
                    "oracle response id mismatch: expected {expected}, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for OracleError {}

/// The default oracle binary path (project-relative).
pub fn default_oracle_path() -> String {
    // Court runners execute from the repository root; the oracle binary lives
    // at tools/oracle/build/oracle.
    "tools/oracle/build/oracle".to_string()
}

pub struct OracleClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    /// Path to the oracle binary (for receipts).
    pub binary: String,
}

impl OracleClient {
    /// Spawns the oracle process at `binary`.
    pub fn spawn(binary: &str) -> Result<OracleClient, OracleError> {
        let path = Path::new(binary);
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| OracleError::Spawn(format!("{binary}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| OracleError::Spawn("child stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| OracleError::Spawn("child stdout unavailable".to_string()))?;
        Ok(OracleClient {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
            binary: binary.to_string(),
        })
    }

    /// Sends a request and returns the paired response.
    pub fn request(&mut self, req: &OracleRequest) -> Result<OracleResponse, OracleError> {
        let value = self.request_value(req)?;
        let resp: OracleResponse =
            serde_json::from_value(value).map_err(|e| OracleError::Protocol(e.to_string()))?;
        if resp.id != req.id {
            return Err(OracleError::Unpaired {
                expected: req.id,
                got: resp.id,
            });
        }
        Ok(resp)
    }

    /// Sends a request and returns the raw response JSON value (used by the
    /// arena court, whose responses have their own shape).
    pub fn request_value(&mut self, req: &OracleRequest) -> Result<serde_json::Value, OracleError> {
        let line = serde_json::to_string(req).map_err(|e| OracleError::Write(e.to_string()))?;
        writeln!(self.stdin, "{line}").map_err(|e| OracleError::Write(e.to_string()))?;

        let mut buf = String::new();
        let n = self
            .stdout
            .read_line(&mut buf)
            .map_err(|e| OracleError::Read(e.to_string()))?;
        if n == 0 {
            return Err(OracleError::Read("oracle closed stdout".to_string()));
        }
        let value: serde_json::Value = {
            // The decode-submsg court produces dumps nested as deep as the
            // message depth (100+ levels), beyond serde_json's default
            // recursion limit of 128. The oracle protocol is trusted output
            // from a pinned oracle binary, so disabling the limit is safe.
            let mut de = serde_json::Deserializer::from_str(buf.trim());
            de.disable_recursion_limit();
            serde_json::Value::deserialize(&mut de)
                .map_err(|e| OracleError::Protocol(e.to_string()))?
        };
        Ok(value)
    }

    /// Allocates a fresh id and sends a primitive read request.
    pub fn primitive(
        &mut self,
        op: crate::protocol::PrimitiveOp,
        payload: &[u8],
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::primitive(id, op, payload);
        self.request(&req)
    }

    /// Sends a skip_value request.
    pub fn skip_value(&mut self, tag: u32, payload: &[u8]) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::skip_value(id, tag, payload);
        self.request(&req)
    }

    /// Sends a skip_group request.
    pub fn skip_group(&mut self, tag: u32, payload: &[u8]) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::skip_group(id, tag, payload);
        self.request(&req)
    }

    /// Protocol self-test: `ping` must return `pong`.
    pub fn ping(&mut self) -> Result<(), OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let resp = self.request(&OracleRequest {
            v: 1,
            id,
            op: "ping".to_string(),
            hex: String::new(),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            options: None,
            b_hex: None,
            script: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        })?;
        if resp.echo.as_deref() != Some("pong") {
            return Err(OracleError::Protocol("ping did not return pong".into()));
        }
        Ok(())
    }

    /// Sends a decode_empty request (real upb_Decode, empty mini table).
    pub fn decode_empty(
        &mut self,
        payload: &[u8],
        depth: u32,
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::decode_empty(id, payload, depth);
        self.request(&req)
    }

    /// Sends a mini_table_inspect request.
    pub fn mini_table_inspect(&mut self, descriptor: &[u8]) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest {
            v: 1,
            id,
            op: "mini_table_inspect".to_string(),
            hex: crate::protocol::hex_encode(descriptor),
            tag: None,
            depth: None,
            md: None,
            mds: None,
            links: None,
            options: None,
            b_hex: None,
            script: None,
            arena: None,
            ops: None,
            gen_ops: None,
            a: None,
            a_ops: None,
            b: None,
            b_ops: None,
            post_ops: None,
            free: None,
        };
        self.request(&req)
    }

    /// Sends a decode_known request (real upb_Decode with a mini table).
    pub fn decode_known(
        &mut self,
        md: &[u8],
        payload: &[u8],
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::decode_known(id, md, payload);
        self.request(&req)
    }

    /// Sends a decode_submsg request (real upb_Decode over a pool of linked
    /// mini tables).
    pub fn decode_submsg(
        &mut self,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        payload: &[u8],
        depth: u32,
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::decode_submsg(id, mds, links, payload, depth);
        self.request(&req)
    }

    /// Sends an encode request: the oracle decodes the payload over the pool
    /// (max depth `depth`) and re-encodes with the real upb_Encode under
    /// `options` (Deterministic = 1, SkipUnknown = 2) and max depth `depth`.
    pub fn encode(
        &mut self,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        payload: &[u8],
        depth: u32,
        options: u32,
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::encode(id, mds, links, payload, depth, options);
        self.request(&req)
    }

    /// Sends a msgop request: decode `payload` (and `payload_b` for merge),
    /// apply the script operation (merge/clear/clone), dump + re-encode.
    #[allow(clippy::too_many_arguments)]
    pub fn msgop(
        &mut self,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        payload: &[u8],
        payload_b: &[u8],
        depth: u32,
        options: u32,
        script: &str,
    ) -> Result<OracleResponse, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::msgop(id, mds, links, payload, payload_b, depth, options, script);
        self.request(&req)
    }

    /// Queries the oracle's arena build constants (arena_info).
    pub fn arena_info(&mut self) -> Result<serde_json::Value, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::arena_info(id);
        self.request_value(&req)
    }

    /// Runs an arena_trace script against the oracle (raw value response).
    pub fn arena_trace(
        &mut self,
        arena: &crate::protocol::ArenaCfg,
        ops: &[crate::protocol::ArenaOp],
        free_at_end: bool,
    ) -> Result<serde_json::Value, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::arena_trace(id, arena.clone(), ops, free_at_end);
        self.request_value(&req)
    }

    /// Runs an arena_fuse script against the oracle (raw value response).
    pub fn arena_fuse(
        &mut self,
        cfg_a: &crate::protocol::ArenaCfg,
        cfg_b: &crate::protocol::ArenaCfg,
        ops_a: &[crate::protocol::ArenaOp],
        ops_b: &[crate::protocol::ArenaOp],
        ops_post: &[crate::protocol::ArenaOp],
    ) -> Result<serde_json::Value, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req =
            OracleRequest::arena_fuse(id, cfg_a.clone(), cfg_b.clone(), ops_a, ops_b, ops_post);
        self.request_value(&req)
    }

    /// Runs an array_trace / map_trace script against the oracle (raw value
    /// response). `op` names the oracle op ("array_trace" / "map_trace").
    pub fn arena_trace_request(
        &mut self,
        op: &str,
        arena: &crate::protocol::ArenaCfg,
        ops: &[crate::protocol::GenOp],
    ) -> Result<serde_json::Value, OracleError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = OracleRequest::gen_trace(id, op, arena.clone(), ops);
        self.request_value(&req)
    }
}

impl Drop for OracleClient {
    fn drop(&mut self) {
        // Close stdin; the oracle exits at EOF.
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

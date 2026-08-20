//! Process client for the oracle server.
//!
//! Spawns `tools/oracle/build/oracle` and performs a versioned JSONL
//! request/response exchange over pipes. Every request receives exactly one
//! response, paired by `id`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::protocol::{OracleRequest, OracleResponse};

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
        let resp: OracleResponse =
            serde_json::from_str(buf.trim()).map_err(|e| OracleError::Protocol(e.to_string()))?;
        if resp.id != req.id {
            return Err(OracleError::Unpaired {
                expected: req.id,
                got: resp.id,
            });
        }
        Ok(resp)
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
        })?;
        if resp.echo.as_deref() != Some("pong") {
            return Err(OracleError::Protocol("ping did not return pong".into()));
        }
        Ok(())
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

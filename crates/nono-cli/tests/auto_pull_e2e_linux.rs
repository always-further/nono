//! Phase 37 Plan 37-05 — Auto-pull e2e integration tests.
//!
//! Verifies REQ-PKGS-04 acceptance #1, #2, #3, #4, plus a 5th test for
//! non-Policy pack rejection (researcher Open Q3 — ~30 LOC additional
//! coverage). Linux-only because the workflow that runs this test pins to
//! ubuntu-24.04 and the production signing path is exercised via the
//! GitHub Actions OIDC token at CI time (D-13 + D-15).
//!
//! File path is LOCKED at this location per D-16.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

#[allow(dead_code)] // consumed by Tasks 2 + 3 tests
const NONO_BIN: &str = env!("CARGO_BIN_EXE_nono");

// ---------------------------------------------------------------------------
// EnvGuard RAII — save/restore env vars per CLAUDE.md "tests run in parallel
// within the same process" rule + Pattern B.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) struct EnvGuard {
    key: String,
    prev: Option<String>,
}

#[allow(dead_code)]
impl EnvGuard {
    pub(crate) fn set(key: &str, val: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        Self {
            key: key.into(),
            prev,
        }
    }

    pub(crate) fn remove(key: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        Self {
            key: key.into(),
            prev,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-endpoint mock TCP server — extends Phase 26-02's spawn_one_shot_server
// pattern (registry_client::tests::spawn_one_shot_server, 50 LOC base).
// NO mockito dev-dep added (D-14: portable-subset constraint preserved).
// ---------------------------------------------------------------------------

/// Spawn an HTTP mock that routes by URL path. Returns
/// `(base_url, JoinHandle, request_counter)`. Accepts up to
/// `routes.len() * 3 + 2` connections then exits (sufficient for the
/// longest auto-pull flow: bundle.json + manifest.json + artifact +
/// retry headroom).
///
/// Routes are a path→(status, body) map. A request whose path does not
/// match any route receives a 404 with body `"not found"`. This shape lets
/// `auto_pull_unknown_name_fails_closed` (Task 2) exercise the fail-closed
/// path with an empty route table.
#[allow(dead_code)]
pub(crate) fn spawn_multi_endpoint_server(
    routes: HashMap<String, (u16, Vec<u8>)>,
) -> (String, thread::JoinHandle<()>, Arc<Mutex<u32>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);
    let counter = Arc::new(Mutex::new(0u32));
    let counter_clone = Arc::clone(&counter);

    let handle = thread::spawn(move || {
        let max_connections = routes.len() * 3 + 2;
        for accept in listener.incoming().take(max_connections) {
            let mut stream = match accept {
                Ok(s) => s,
                Err(_) => return,
            };
            *counter_clone.lock().unwrap() += 1;

            let mut buf = [0u8; 4096];
            let mut accumulated = Vec::with_capacity(4096);
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                accumulated.extend_from_slice(&buf[..n]);
                if accumulated.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if accumulated.len() > 64 * 1024 {
                    break;
                }
            }

            let request_line = std::str::from_utf8(&accumulated)
                .ok()
                .and_then(|s| s.lines().next())
                .unwrap_or("");
            let path = request_line.split_whitespace().nth(1).unwrap_or("/");

            let (status, body) = routes
                .get(path)
                .cloned()
                .unwrap_or((404, b"not found".to_vec()));
            let status_text = match status {
                200 => "OK",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let response_head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status,
                status_text,
                body.len()
            );
            let _ = stream.write_all(response_head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (base_url, handle, counter)
}

// ---------------------------------------------------------------------------
// Fixture loader — reads the CI-signed pack from NONO_FIXTURE_PACK_DIR.
// Task 4's CI workflow step populates this dir before invoking the tests.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn fixture_pack_dir() -> Option<std::path::PathBuf> {
    let path = std::env::var("NONO_FIXTURE_PACK_DIR").ok()?;
    let pb = std::path::PathBuf::from(path);
    if pb.is_dir() {
        Some(pb)
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn read_fixture(name: &str) -> Vec<u8> {
    let dir = fixture_pack_dir().expect(
        "NONO_FIXTURE_PACK_DIR not set — run via Phase 37 CI workflow OR locally with sigstore-sign keyless",
    );
    std::fs::read(dir.join(name)).expect("read fixture file")
}

// ---------------------------------------------------------------------------
// Helper smoke test — verifies the mock server helper end-to-end without
// invoking the nono binary. Lets `cargo test --no-run` + a single
// `cargo test spawn_multi_endpoint_server_smoke` prove the scaffold works
// before Tasks 2 + 3 add their tests.
// ---------------------------------------------------------------------------

#[test]
fn spawn_multi_endpoint_server_smoke() {
    use std::net::TcpStream;

    let mut routes = HashMap::new();
    routes.insert("/ping".to_string(), (200, b"pong".to_vec()));
    let (base_url, _handle, counter) = spawn_multi_endpoint_server(routes);

    // Parse "http://127.0.0.1:PORT" -> "127.0.0.1:PORT".
    let addr_part = base_url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(addr_part).expect("connect mock");
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let resp_str = String::from_utf8_lossy(&response);

    assert!(
        resp_str.contains("pong"),
        "expected pong in response; got: {resp_str}"
    );
    assert_eq!(
        *counter.lock().unwrap(),
        1,
        "expected exactly 1 request"
    );
}

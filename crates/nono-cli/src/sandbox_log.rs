#[cfg(target_os = "macos")]
use nono::SandboxViolation;
#[cfg(target_os = "macos")]
use serde_json::Value;
#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "macos")]
use tracing::debug;

#[cfg(target_os = "macos")]
const LOG_STREAM_PREDICATE: &str = "((processID == 0) AND (senderImagePath CONTAINS \"/Sandbox\")) OR (process == \"sandboxd\") OR (subsystem == \"com.apple.sandbox.reporting\")";
#[cfg(target_os = "macos")]
const MAX_VIOLATIONS: usize = 50;

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SharedViolations {
    seen: BTreeSet<(String, String)>,
    violations: Vec<SandboxViolation>,
}

#[cfg(target_os = "macos")]
pub struct SandboxLogCollector {
    child: Child,
    reader_thread: Option<JoinHandle<()>>,
    shared: Arc<Mutex<SharedViolations>>,
}

#[cfg(target_os = "macos")]
impl SandboxLogCollector {
    #[must_use]
    pub fn start(child_pid: i32) -> Option<Self> {
        let mut child = match Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--level",
                "debug",
                "--predicate",
                LOG_STREAM_PREDICATE,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                debug!("sandbox log stream failed to spawn: {e}");
                return None;
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                debug!("sandbox log stream missing stdout");
                return None;
            }
        };

        let shared = Arc::new(Mutex::new(SharedViolations::default()));
        let thread_shared = Arc::clone(&shared);
        let reader_thread = thread::Builder::new()
            .name("nono-sandbox-log".to_string())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    let Ok(line) = line else {
                        break;
                    };

                    let Some(violation) = parse_violation_line(child_pid, &line) else {
                        continue;
                    };

                    let mut guard = match thread_shared.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    let key = (
                        violation.operation.clone(),
                        violation.target.clone().unwrap_or_default(),
                    );
                    if !guard.seen.insert(key) {
                        continue;
                    }
                    guard.violations.push(violation);
                    if guard.violations.len() >= MAX_VIOLATIONS {
                        break;
                    }
                }
            })
            .ok()?;

        Some(Self {
            child,
            reader_thread: Some(reader_thread),
            shared,
        })
    }

    #[must_use]
    pub fn finish(mut self) -> Vec<SandboxViolation> {
        let _ = self.child.kill();
        let _ = self.child.wait();

        if let Some(reader_thread) = self.reader_thread.take() {
            let _ = reader_thread.join();
        }

        match Arc::try_unwrap(self.shared) {
            Ok(shared) => match shared.into_inner() {
                Ok(shared) => shared.violations,
                Err(poisoned) => poisoned.into_inner().violations,
            },
            Err(shared) => match shared.lock() {
                Ok(shared) => shared.violations.clone(),
                Err(poisoned) => poisoned.into_inner().violations.clone(),
            },
        }
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub struct SandboxLogCollector;

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
impl SandboxLogCollector {
    #[must_use]
    pub fn start(_child_pid: i32) -> Option<Self> {
        None
    }

    #[must_use]
    pub fn finish(self) -> Vec<nono::SandboxViolation> {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn parse_violation_line(child_pid: i32, line: &str) -> Option<SandboxViolation> {
    let value: Value = serde_json::from_str(line).ok()?;
    parse_violation_value(child_pid, &value)
}

#[cfg(target_os = "macos")]
fn parse_violation_value(child_pid: i32, value: &Value) -> Option<SandboxViolation> {
    if let Some(message) = value.get("eventMessage").and_then(Value::as_str) {
        if let Some(violation) = parse_event_message(child_pid, message) {
            return Some(violation);
        }
    }

    let metadata = value.get("eventMessage").and_then(|event_message| {
        event_message
            .as_str()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
    });
    if let Some(violation) = metadata
        .as_ref()
        .and_then(|metadata| parse_metadata_violation(child_pid, metadata))
    {
        return Some(violation);
    }

    let metadata = value
        .get("metadata")
        .or_else(|| value.get("MetaData"))
        .or_else(|| value.get("composedMessage"))
        .and_then(|metadata| {
            if metadata.is_object() {
                Some(metadata.clone())
            } else {
                metadata
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
            }
        });

    metadata
        .as_ref()
        .and_then(|metadata| parse_metadata_violation(child_pid, metadata))
}

#[cfg(target_os = "macos")]
fn parse_metadata_violation(child_pid: i32, metadata: &Value) -> Option<SandboxViolation> {
    let pid = metadata
        .get("pid")
        .and_then(Value::as_i64)
        .or_else(|| metadata.get("processID").and_then(Value::as_i64))?;
    if pid != i64::from(child_pid) {
        return None;
    }

    let operation = metadata
        .get("operation")
        .and_then(Value::as_str)
        .map(str::to_string)?;
    let target = metadata
        .get("target")
        .and_then(Value::as_str)
        .or_else(|| metadata.get("path").and_then(Value::as_str))
        .or_else(|| metadata.get("global-name").and_then(Value::as_str))
        .map(str::to_string);

    Some(SandboxViolation { operation, target })
}

#[cfg(target_os = "macos")]
fn parse_event_message(child_pid: i32, message: &str) -> Option<SandboxViolation> {
    let first_line = message.lines().next()?.trim();
    let sandbox_line = first_line
        .split_once("Sandbox: ")
        .map(|(_, suffix)| suffix)
        .or_else(|| first_line.strip_prefix("Sandbox: "))?;

    let pid_token = format!("({child_pid})");
    let (_, remainder) = sandbox_line.split_once(&pid_token)?;
    let remainder = remainder.trim_start();
    let remainder = remainder.strip_prefix("deny(")?;
    let (_, detail) = remainder.split_once(") ")?;
    let detail = detail.trim();
    let (operation, target) = match detail.split_once(' ') {
        Some((operation, target)) => (operation.to_string(), Some(target.trim().to_string())),
        None => (detail.to_string(), None),
    };

    Some(SandboxViolation { operation, target })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{parse_event_message, parse_violation_line};

    #[test]
    fn parses_file_violation_line() {
        let msg = "Sandbox: cat(1234) deny(1) file-read-data /Users/test/.ssh/id_rsa";
        let violation = parse_event_message(1234, msg).expect("violation");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target.as_deref(), Some("/Users/test/.ssh/id_rsa"));
    }

    #[test]
    fn parses_mach_violation_line() {
        let msg = "Sandbox: codex(14485) deny(1) mach-lookup com.apple.logd";
        let violation = parse_event_message(14485, msg).expect("violation");
        assert_eq!(violation.operation, "mach-lookup");
        assert_eq!(violation.target.as_deref(), Some("com.apple.logd"));
    }

    #[test]
    fn parses_ndjson_metadata_violation() {
        let line = r#"{"eventMessage":"Sandbox: cat(1234) deny(1) file-read-data /Users/test/.ssh/id_rsa","subsystem":"com.apple.sandbox.reporting","category":"violation","MetaData":{"operation":"file-read-data","pid":1234,"target":"/Users/test/.ssh/id_rsa"}}"#;
        let violation = parse_violation_line(1234, line).expect("violation");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target.as_deref(), Some("/Users/test/.ssh/id_rsa"));
    }

    #[test]
    fn ignores_other_pids() {
        let msg = "Sandbox: cat(9999) deny(1) file-read-data /tmp/x";
        assert!(parse_event_message(1234, msg).is_none());
    }
}

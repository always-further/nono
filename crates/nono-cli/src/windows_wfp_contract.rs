use serde::{Deserialize, Serialize};

pub const WFP_RUNTIME_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpRuntimeActivationRequest {
    pub protocol_version: u32,
    pub request_kind: String,
    pub network_mode: String,
    pub preferred_backend: String,
    pub active_backend: String,
    pub runtime_target: String,
    pub tcp_connect_ports: Vec<u16>,
    pub tcp_bind_ports: Vec<u16>,
    pub localhost_ports: Vec<u16>,
    pub target_program_path: Option<String>,
    pub session_sid: Option<String>,
    pub outbound_rule_name: Option<String>,
    pub inbound_rule_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpRuntimeActivationResponse {
    pub protocol_version: u32,
    pub status: String,
    pub details: String,
}

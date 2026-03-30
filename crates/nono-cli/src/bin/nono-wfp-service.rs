//! Windows WFP backend service placeholder.
//!
//! This binary is the first repo-owned artifact for the future Windows WFP
//! backend. It establishes the expected Windows service contract without
//! claiming working service-host or enforcement behavior yet.

use std::process::ExitCode;

const SERVICE_NAME: &str = "nono-wfp-service";
const SERVICE_MODE_ARG: &str = "--service-mode";
const PROBE_RUNTIME_ACTIVATION_ARG: &str = "--probe-runtime-activation";

fn print_help() {
    println!("nono-wfp-service {}", env!("CARGO_PKG_VERSION"));
    println!("Windows WFP backend service placeholder");
    println!();
    println!("This binary defines the current Windows service contract for the");
    println!("future WFP backend. Service registration and service-host runtime");
    println!("still fail closed until the real backend is implemented.");
    println!();
    println!("Service contract:");
    println!("  service name: {SERVICE_NAME}");
    println!("  startup args: {SERVICE_MODE_ARG}");
    println!();
    println!("Supported options:");
    println!("  --help                 Show this message");
    println!("  --version              Show version information");
    println!("  --print-service-contract");
    println!("                         Print the expected Windows service contract");
    println!(
        "  {PROBE_RUNTIME_ACTIVATION_ARG:<22}Probe the placeholder runtime activation contract"
    );
    println!("  {SERVICE_MODE_ARG:<22}Run the placeholder service entrypoint");
}

fn print_service_contract() {
    println!("service_name={SERVICE_NAME}");
    println!("startup_args={SERVICE_MODE_ARG}");
}

fn run_service_mode() -> ExitCode {
    eprintln!(
        "nono-wfp-service: service runtime is not implemented yet; \
         registration may target '{SERVICE_NAME} {SERVICE_MODE_ARG}', but startup still fails closed"
    );
    ExitCode::from(3)
}

fn probe_runtime_activation() -> ExitCode {
    println!("activation=not-implemented");
    eprintln!(
        "nono-wfp-service: runtime activation handshake is not implemented yet; \
         service and driver may be registered, but WFP enforcement still fails closed"
    );
    ExitCode::from(4)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {
            eprintln!(
                "nono-wfp-service: missing required mode; use \
                 --print-service-contract, {PROBE_RUNTIME_ACTIVATION_ARG}, or {SERVICE_MODE_ARG}"
            );
            ExitCode::from(2)
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--print-service-contract") => {
            print_service_contract();
            ExitCode::SUCCESS
        }
        Some(PROBE_RUNTIME_ACTIVATION_ARG) => probe_runtime_activation(),
        Some(SERVICE_MODE_ARG) => run_service_mode(),
        Some(other) => {
            eprintln!("nono-wfp-service: unsupported argument '{other}'");
            eprintln!(
                "Run with --help to inspect the current service contract \
                 or --print-service-contract for machine-readable output."
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_contract_output_is_stable() {
        let text = format!("service_name={SERVICE_NAME}\nstartup_args={SERVICE_MODE_ARG}\n");
        assert!(text.contains("service_name=nono-wfp-service"));
        assert!(text.contains("startup_args=--service-mode"));
    }

    #[test]
    fn service_mode_fails_closed() {
        assert_eq!(run_service_mode(), ExitCode::from(3));
    }

    #[test]
    fn runtime_activation_probe_fails_closed() {
        assert_eq!(probe_runtime_activation(), ExitCode::from(4));
    }
}

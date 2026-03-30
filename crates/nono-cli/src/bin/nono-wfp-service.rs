//! Windows WFP backend service placeholder.
//!
//! This binary is the first repo-owned artifact for the future Windows WFP
//! backend. It is intentionally not a working service yet. Its presence gives
//! the Windows readiness probe a concrete binary contract to check, while the
//! service and driver installation flow remain future work.

use std::process::ExitCode;

fn print_help() {
    println!("nono-wfp-service {}", env!("CARGO_PKG_VERSION"));
    println!("Windows WFP backend service placeholder");
    println!();
    println!("This binary exists to establish the expected Windows WFP backend");
    println!("artifact contract. Service installation and runtime enforcement");
    println!("are not implemented yet.");
    println!();
    println!("Supported options:");
    println!("  --help       Show this message");
    println!("  --version    Show version information");
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {
            eprintln!("nono-wfp-service: Windows WFP backend service mode is not implemented yet");
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
        Some(other) => {
            eprintln!("nono-wfp-service: unsupported argument '{other}'");
            eprintln!("Run with --help to inspect the current placeholder surface.");
            ExitCode::from(2)
        }
    }
}

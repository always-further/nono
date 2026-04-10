use clap::Parser;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::exit;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Remote host IP to connect to
    #[arg(long)]
    host: IpAddr,

    /// Remote port to connect to
    #[arg(long)]
    port: u16,

    /// Expect the connection to fail
    #[arg(long)]
    should_fail: bool,
}

fn main() {
    let args = Args::parse();
    let addr = SocketAddr::new(args.host, args.port);
    let timeout = Duration::from_secs(2);

    println!("Attempting to connect to {} (timeout: 2s)...", addr);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => {
            if args.should_fail {
                eprintln!("Error: Connection succeeded, but was expected to fail.");
                exit(1);
            } else {
                println!("Success: Connection established.");
                exit(0);
            }
        }
        Err(e) => {
            if args.should_fail {
                println!("Success: Connection failed as expected. Error: {}", e);
                exit(0);
            } else {
                eprintln!(
                    "Error: Connection failed, but was expected to succeed. Error: {}",
                    e
                );
                exit(1);
            }
        }
    }
}

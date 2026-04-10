use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn parse_port_arg() -> std::result::Result<u16, String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--connect-port" {
            let Some(value) = args.next() else {
                return Err("missing value for --connect-port".to_string());
            };
            return value
                .parse::<u16>()
                .map_err(|e| format!("invalid --connect-port value `{value}`: {e}"));
        }
    }

    Err("missing --connect-port".to_string())
}

fn main() {
    let port = match parse_port_arg() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => {
            println!("connected");
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("connect failed: {err}");
            std::process::exit(42);
        }
    }
}

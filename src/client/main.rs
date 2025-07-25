use pea_2_pea::SERVER_PORT;

use std::{
    io::{ErrorKind, Read, Write},
    net::UdpSocket,
    process::exit,
    time::Duration,
};

#[derive(clap::Parser)]
#[command(name = "pea_2_pea")]
#[command(about = "A CLI tool for pea_2_pea P2P vpn client")]
struct Cli {
    #[arg(short = 'r', long = "registrar")]
    #[arg(help = "registrar ip address or hostname")]
    registrar: String,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(short = 'V', long = "version")]
    version: bool,

    #[arg(short = 'p', long = "registrar-port")]
    #[arg(help = format!("Port number for the registrar service (1-65535) Default: {}", SERVER_PORT))]
    registrar_port: Option<u16>,

    #[arg(short = 'P', long = "bind-port")]
    bind_port: Option<u16>,
}

fn main() -> std::io::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    {
        let socket: UdpSocket = (|| -> std::io::Result<UdpSocket> {
            let mut port: u16;
            match cli.bind_port {
                Some(port_proveded) => port = port_proveded,
                None => port = 59999, // Magic number
            }
            loop {
                port += 1;
                match UdpSocket::bind(format!("0.0.0.0:{}", port)) {
                    Ok(socket) => return Ok(socket),
                    Err(_) => continue, // Retry on error
                }
            }
        })()
        .expect("Failed to bind to any available port");

        socket.set_read_timeout(Some(Duration::new(10, 0)))?; // set timeout to 10 seconds

        // send query request to get server public key
        let server_port: u16 = (|| -> u16 {
            match cli.bind_port {
                Some(port_proveded) => return port_proveded,
                None => return pea_2_pea::SERVER_PORT,
            }
        })();

        let server_SocketAddr: core::net::SocketAddr = format!("{}:{}", cli.registrar, server_port)
            .parse()
            .unwrap();

        {
            let mut query_byte: [u8; 1] = [0; 1];
            query_byte[0] = pea_2_pea::ServerMethods::QUERY as u8;
            match socket.send_to(&query_byte, &server_SocketAddr) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error snding data: {}", e);
                }
            }
        }

        let mut buf: [u8; pea_2_pea::BUFFER_SIZE] = [0; pea_2_pea::BUFFER_SIZE];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((data_length, src)) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    // timedout
                    continue;
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    std::process::exit(-4);
                }
            }
            break;
        }
    }
    Ok(())
}

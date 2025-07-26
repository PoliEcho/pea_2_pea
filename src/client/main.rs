use pea_2_pea::SERVER_PORT;

use std::{
    io::{Error, ErrorKind, Read, Write},
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

    #[arg(short = 'p', long = "registrar-port")]
    #[arg(help = format!("optional Port number for the registrar service (1-65535) Default: {}", SERVER_PORT))]
    registrar_port: Option<u16>,

    #[arg(short = 'n', long = "network-id")]
    #[arg(help = "your virtual network id that allows other people to connect to you")]
    network_id: String,

    #[arg(short = 'P', long = "password")]
    #[arg(
        help = "encryption password for your virtual network if not provided transmitions will be unencrypted"
    )]
    password: Option<String>,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(short = 'V', long = "version")]
    version: bool,
}

fn main() -> std::io::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    {
        let socket: UdpSocket = (|| -> std::io::Result<UdpSocket> {
            match UdpSocket::bind("0.0.0.0:0") {
                // bind to OS assigned random port
                Ok(socket) => return Ok(socket),
                Err(e) => Err(e), // exit on error
            }
        })()
        .expect("Failed to bind to any available port");

        socket.set_read_timeout(Some(Duration::new(10, 0)))?; // set timeout to 10 seconds

        // send query request to get server public key
        let server_port: u16 = (|| -> u16 {
            match cli.registrar_port {
                Some(port_proveded) => return port_proveded,
                None => return pea_2_pea::SERVER_PORT,
            }
        })();

        #[allow(non_snake_case)] // i think this is valid snake case but rustc doesnt think so
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

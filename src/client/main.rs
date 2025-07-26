use pea_2_pea::*;

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
    if cli.network_id.len() > 0xff {
        eprintln!("network id cannot have more then 255 charactes");
        exit(7); // posix for E2BIG
    }
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

        let server_port: u16 = (|| -> u16 {
            match cli.registrar_port {
                Some(port_proveded) => return port_proveded,
                None => return SERVER_PORT,
            }
        })();

        #[allow(non_snake_case)] // i think this is valid snake case but rustc doesnt think so
        let server_SocketAddr: core::net::SocketAddr = format!("{}:{}", cli.registrar, server_port)
            .parse()
            .unwrap();

        let mut buf: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        let mut data_lenght;
        loop {
            match socket.send_to(&[ServerMethods::QUERY as u8], &server_SocketAddr) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    panic!("Error sending data: {}", e);
                }
            }

            match socket.recv_from(&mut buf) {
                Ok((data_length_recved, _src)) => {
                    data_lenght = data_length_recved;
                    if buf[0] != 0 {
                        continue;
                    }
                    break;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    // timedout
                    continue;
                }
                Err(e) => {
                    panic!("Error receiving data: {}", e);
                }
            }
        }

        let mut public_sock_addr: Vec<u8> = buf[1..data_lenght].to_vec();

        // register network

        buf[0] = ServerMethods::REGISTER as u8;
        buf[RegisterRequestDataPositions::ENCRYPTED as usize] = match cli.password {
            Some(_) => true as u8,
            None => false as u8,
        };
        buf[RegisterRequestDataPositions::ID_LEN as usize] = cli.network_id.len() as u8;
        buf[RegisterRequestDataPositions::SOCKADDR_LEN as usize] =
            server_SocketAddr.to_string().len() as u8;

        buf[RegisterRequestDataPositions::DATA as usize
            ..RegisterRequestDataPositions::DATA as usize + cli.network_id.len()]
            .copy_from_slice(cli.network_id.as_bytes());// store network id



        match cli.password {
            Some(s) => {},
            None => {},// do nothig
        }

        

        buf[RegisterRequestDataPositions::DATA as usize + cli.network_id.len()..RegisterRequestDataPositions::DATA as usize + cli.network_id.len() + ]

        match buf[0] {
            x if x == ServerResponse::OK as u8 => {
                eprintln!("network registered");
            }

            x if x == ServerResponse::GENERAL_ERROR as u8 => {
                eprintln!(
                    "{}",
                    match std::str::from_utf8(&buf[1..data_lenght]) {
                        Ok(s) => s.to_string(),
                        Err(e) => {
                            panic!("id to utf-8 failed: {}", e);
                        }
                    }
                )
            }
            x if x == ServerResponse::ID_EXISTS as u8 => {
                panic!("network ID already exist try differnt one!");
            }

            _ => {
                panic!("unknown responce from server code: 0x{:02x}", buf[0])
            }
        }
    }
    Ok(())
}

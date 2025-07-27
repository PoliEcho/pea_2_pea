mod net;
use pea_2_pea::*;
use rand::RngCore;

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
        // query here
        let mut data_lenght: usize = net::query_request(&mut buf, &server_SocketAddr, socket)?;

        let mut public_sock_addr: Vec<u8> = buf[1..data_lenght].to_vec();

        // register network

        let mut salt: Option<[u8; SALT_AND_IV_SIZE as usize]>;
    }
    Ok(())
}

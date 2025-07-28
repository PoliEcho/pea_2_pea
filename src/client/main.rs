mod net;
mod types;
use pea_2_pea::*;
use rand::RngCore;

use std::{net::UdpSocket, process::exit, time::Duration};

use crate::types::Network;

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
        let public_sock_addr_raw: String =
            match net::query_request(&mut buf, &server_SocketAddr, &socket) {
                Ok(s) => s,
                Err(e) => return Err(ServerErrorResponses::into_io_error(e)),
            };

        let mut salt: [u8; SALT_AND_IV_SIZE] = [0u8; SALT_AND_IV_SIZE];
        let mut iv: [u8; SALT_AND_IV_SIZE] = [0u8; SALT_AND_IV_SIZE];
        let (public_sock_addr, encryption_key) = match cli.password {
            Some(ref p) => {
                let mut rng = rand::rng();
                rng.fill_bytes(&mut salt);
                rng.fill_bytes(&mut iv);
                let enc_key_tmp = shared::crypto::derive_key_from_password(p.as_bytes(), &salt);
                (
                    shared::crypto::encrypt(&enc_key_tmp, &iv, public_sock_addr_raw.as_bytes())
                        .unwrap()
                        .into_boxed_slice(),
                    enc_key_tmp,
                )
            }
            None => (
                public_sock_addr_raw.as_bytes().to_vec().into_boxed_slice(),
                [0u8; 32],
            ),
        };

        let virtual_network: Network = {
            match net::get_request(
                &mut buf,
                &server_SocketAddr,
                &socket,
                &cli.network_id,
                &cli.password,
            ) {
                Ok(n) => {
                    eprintln!("Network exists joining it");
                    let _ = net::send_heartbeat(
                        &mut buf,
                        &server_SocketAddr,
                        &socket,
                        &n,
                        &public_sock_addr,
                        &iv,
                    );
                    n
                }
                Err(e) if e.kind() == ServerResponse::ID_DOESNT_EXIST => {
                    eprintln!("Network does not exist creating it!");
                    let tmp_v_net: Network = Network::new(
                        match cli.password {
                            Some(_) => true,
                            None => false,
                        },
                        encryption_key,
                        cli.network_id,
                        salt,
                        Vec::with_capacity(1),
                    );
                    net::register_request(
                        &mut buf,
                        &server_SocketAddr,
                        &socket,
                        &tmp_v_net,
                        &public_sock_addr,
                        &iv,
                    )
                    .unwrap();
                    tmp_v_net
                }
                Err(e) => {
                    eprintln!("Failed to get data from server. Reason: {}", e);
                    exit(5); //EIO
                }
            }
        };
    }
    Ok(())
}

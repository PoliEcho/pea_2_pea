mod net;
mod tun;
mod types;
use colored::Colorize;
use pea_2_pea::*;
use rand::RngCore;
use rayon::prelude::*;

use std::{
    net::UdpSocket,
    process::exit,
    sync::{Arc, RwLock},
    time::Duration,
};

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

    #[arg(short = 'i', long = "interface-name")]
    #[arg(help = "select tun interface name Default: pea0")]
    if_name: Option<String>,

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
    let mut buf: [u8; UDP_BUFFER_SIZE] = [0; UDP_BUFFER_SIZE];
    let (socket, virtual_network, my_public_sock_addr) = {
        let socket: Arc<UdpSocket> = Arc::new(|| -> std::io::Result<UdpSocket> {
            match UdpSocket::bind("0.0.0.0:0") {
                // bind to OS assigned random port
                Ok(socket) => return Ok(socket),
                Err(e) => Err(e), // exit on error
            }
        })()
        .expect("Failed to bind to any available port")
        .into();

        #[cfg(not(feature = "no-timeout"))]
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
            .expect(&format!(
                "{}:{} is invalid sock addr",
                cli.registrar, server_port
            ));

        // query here
        let public_sock_addr_raw: String =
            match net::query_request(&mut buf, &server_SocketAddr, &socket) {
                Ok(s) => s,
                Err(e) => return Err(ServerErrorResponses::into_io_error(e)),
            };
        println!(
            "{} my bublic sockaddr: {}",
            "[LOG]".blue(),
            public_sock_addr_raw
        );

        let mut salt: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        let mut iv: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        let (mut public_sock_addr, encryption_key) = match cli.password {
            Some(ref p) => {
                let mut rng = rand::rng();
                rng.fill_bytes(&mut salt);
                rng.fill_bytes(&mut iv);
                let enc_key_tmp = shared::crypto::derive_key_from_password(p.as_bytes(), &salt);
                #[cfg(debug_assertions)]
                eprintln!(
                    "key: {}",
                    enc_key_tmp
                        .iter()
                        .map(|x| format!("{:02X} ", x))
                        .collect::<String>()
                );
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

        let virtual_network: Arc<RwLock<Network>> = RwLock::new({
            match net::get_request(
                &mut buf,
                &server_SocketAddr,
                &socket,
                &cli.network_id,
                &cli.password,
            ) {
                Ok(n) => {
                    eprintln!("Network exists joining it");
                    public_sock_addr =
                        shared::crypto::encrypt(&n.key, &iv, public_sock_addr_raw.as_bytes())
                            .unwrap()
                            .into_boxed_slice();
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
        })
        .into();
        (
            socket,
            virtual_network,
            types::EncryptablePulicSockAddr::new(iv, public_sock_addr),
        )
    };

    {
        // all loops here will be auto skiped if there are no peers yet
        let mut ips_used: [bool; u8::MAX as usize + 1] = [false; u8::MAX as usize + 1];
        ips_used[0] = true; // ignore net addr
        ips_used[u8::MAX as usize] = true; // ignore broadcast
        println!(
            "{} reaching to other peers to obtain ip address",
            "[LOG]".blue()
        );
        let mut network_write_lock = virtual_network.write().unwrap(); // avoid deadlock

        let encrypted = network_write_lock.encrypted;
        let key = network_write_lock.key;
        network_write_lock.peers.iter_mut().for_each(|peer| {
            println!(
                "{} firing salvo of PUNCHING packets to {}",
                "[LOG]".blue(),
                peer.sock_addr
            );
            for _ in 0..MAPPING_SHOT_COUNT {
                match socket.send_to(&[P2PMethods::DO_NOTHING as u8], peer.sock_addr) {
                    Ok(s) => {
                        #[cfg(debug_assertions)]
                        eprintln!("send {} bytes", s);
                    }
                    Err(e) => eprintln!("{} failed to send puching packet: {}", "[ERROR]".red(), e),
                }
            }
            println!(
                "{} packets away!, awiting a bit for NAT mappings to estabilish",
                "[LOG]".blue()
            );
            std::thread::sleep(Duration::from_millis(200));

            match net::P2P_query(&mut buf, &peer.sock_addr, &socket, encrypted, key) {
                Ok(ip) => {
                    ips_used[ip.octets()[3] as usize] = true;
                    peer.private_ip = ip;
                }
                Err(e) => {
                    eprintln!(
                        "{} while getting ip from peer: {}, Error: {}",
                        "[ERROR]".red(),
                        peer.sock_addr,
                        e
                    );
                }
            }
        });

        network_write_lock.private_ip = std::net::Ipv4Addr::new(
            DEFAULT_NETWORK_PREFIX[0],
            DEFAULT_NETWORK_PREFIX[1],
            DEFAULT_NETWORK_PREFIX[2],
            ips_used.par_iter().position_first(|&b| !b).unwrap() as u8,
        ); // find first element that is false

        network_write_lock
            .peers
            .retain(|peer| peer.private_ip != std::net::Ipv4Addr::UNSPECIFIED); // remove all peers without ip

        network_write_lock.peers.iter().for_each(|peer| {
            match net::P2P_hello(
                &mut buf,
                &peer.sock_addr,
                &socket,
                network_write_lock.private_ip,
                encrypted,
                key,
            ) {
                Ok(_) => eprintln!(
                    "{} registered with peer: {}",
                    "[SUCCESS]".green(),
                    peer.sock_addr
                ),
                Err(e) => eprintln!(
                    "{} failed to register with peer: {}, Error: {}",
                    "[ERROR]".red(),
                    peer.sock_addr,
                    e
                ),
            }
        });
    }

    let tun_iface = Arc::new(
        match tun::create_tun_interface(virtual_network.read().unwrap().private_ip, cli.if_name) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "{} failed to create Tun interface, Error: {}, are you running as root?",
                    "[CRITICAL]".red().bold(),
                    e
                );
                return Err(e);
            }
        },
    );

    // timeout is no longer needed
    #[cfg(not(feature = "no-timeout"))]
    socket.set_read_timeout(None)?;

    {
        let tun_iface_clone = tun_iface.clone();
        let socket_clone = socket.clone();
        let virtual_network_clone = virtual_network.clone();

        std::thread::spawn(move || {
            tun::read_tun_iface(tun_iface_clone, socket_clone, virtual_network_clone)
        });
    } // just let me have my thread

    smol::block_on(async {
        loop {
            buf.fill(0);
            match socket.recv_from(&mut buf) {
                Ok((data_lenght, src)) => {
                    #[cfg(debug_assertions)]
                    eprintln!("recived method 0x{:02x} spawning handler", buf[0]);
                    smol::spawn(net::handle_incoming_connection(
                        buf,
                        src,
                        virtual_network.clone(),
                        tun_iface.clone(),
                        socket.clone(),
                        data_lenght,
                    ))
                    .await;
                }
                Err(e) => {
                    eprintln!(
                        "{} failed to read from socket Error: {}\n{}",
                        "[WARNING]".red(),
                        e,
                        "Retrying".bright_yellow()
                    );
                }
            }
        }
    });

    Ok(())
}

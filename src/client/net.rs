use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    str::FromStr,
    sync::{Arc, RwLock},
};

use super::types;
use colored::Colorize;
use pea_2_pea::{shared::net::send_and_recv_with_retry, *};
use rand::{RngCore, rng};

pub fn query_request(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
) -> Result<String, ServerErrorResponses> {
    #[cfg(debug_assertions)]
    println!("QUERY method");
    match send_and_recv_with_retry(
        buf,
        &[ServerMethods::QUERY as u8],
        dst,
        socket,
        STANDARD_RETRY_MAX,
    ) {
        Ok((data_lenght, _)) => {
            return Ok(match std::str::from_utf8(&buf[1..data_lenght]) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    eprint!("id to utf-8 failed: {}", e);
                    return Err(ServerErrorResponses::GENERAL_ERROR(format!("{}", e)));
                }
            });
        }
        Err(e) => return Err(e),
    }
}

pub fn register_request(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
    network: &types::Network,
    public_sock_addr: &Box<[u8]>,
    iv: &[u8; BLOCK_SIZE as usize],
) -> Result<usize, ServerErrorResponses> {
    #[cfg(debug_assertions)]
    println!("REGISTER method");
    let mut send_buf: Box<[u8]> = vec![
        0u8;
        RegisterRequestDataPositions::DATA as usize
            + network.net_id.len()
            + public_sock_addr.len()
    ]
    .into_boxed_slice();

    #[cfg(debug_assertions)]
    eprintln!(
        "registering network:\niv: {}\nSockAddr: {}\nsalt: {}",
        iv.iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
        public_sock_addr
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
        network
            .salt
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
    );

    send_buf[0] = ServerMethods::REGISTER as u8; // set metod identification byte
    send_buf[RegisterRequestDataPositions::ENCRYPTED as usize] = network.encrypted as u8;

    send_buf[RegisterRequestDataPositions::ID_LEN as usize] = network.net_id.len() as u8;

    send_buf[RegisterRequestDataPositions::DATA as usize
        ..RegisterRequestDataPositions::DATA as usize + network.net_id.len()]
        .copy_from_slice(network.net_id.as_bytes()); // store network id

    send_buf[RegisterRequestDataPositions::IV as usize
        ..RegisterRequestDataPositions::IV as usize + BLOCK_SIZE as usize]
        .copy_from_slice(iv); // copy iv ad salt do the request
    send_buf[RegisterRequestDataPositions::SALT as usize
        ..RegisterRequestDataPositions::SALT as usize + BLOCK_SIZE as usize]
        .copy_from_slice(&network.salt);

    send_buf[RegisterRequestDataPositions::SOCKADDR_LEN as usize] = public_sock_addr.len() as u8;

    send_buf[RegisterRequestDataPositions::DATA as usize + network.net_id.len()
        ..RegisterRequestDataPositions::DATA as usize
            + network.net_id.len()
            + public_sock_addr.len()]
        .copy_from_slice(&public_sock_addr);

    match send_and_recv_with_retry(buf, &send_buf, dst, socket, STANDARD_RETRY_MAX) {
        Ok((data_lenght, _)) => return Ok(data_lenght),
        Err(e) => return Err(e),
    }
}

pub fn get_request(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
    network_id: &String,
    password: &Option<String>,
) -> Result<types::Network, ServerErrorResponses> {
    #[cfg(debug_assertions)]
    println!("GET method");
    let mut send_buf: Box<[u8]> =
        vec![0u8; GetRequestDataPositions::ID as usize + network_id.len()].into_boxed_slice();
    send_buf[0] = ServerMethods::GET as u8;
    send_buf[GetRequestDataPositions::ID as usize
        ..GetRequestDataPositions::ID as usize + network_id.len()]
        .copy_from_slice(network_id.as_bytes());

    // this is unused now it will be used to bounds check in the future
    let data_lenght: usize =
        match send_and_recv_with_retry(buf, &send_buf, dst, socket, STANDARD_RETRY_MAX) {
            Ok((data_lenght, _)) => data_lenght,
            Err(e) => return Err(e),
        };

    let encrypted: bool = if buf[GetResponseDataPositions::ENCRYPTED as usize] != 0 {
        match password {
            Some(_) => true,
            None => panic!("Network is encrypted but no password was provided"),
        }
    } else {
        match password {
            Some(_) => {
                eprintln!(
                    "Warning! Network is not encrypted but password was provided, ignoring password!"
                )
            }
            None => {}
        }
        false
    };

    let mut num_of_clients: u8 = buf[GetResponseDataPositions::NUM_OF_CLIENTS as usize];

    let salt: [u8; BLOCK_SIZE as usize] = buf[GetResponseDataPositions::SALT as usize
        ..GetResponseDataPositions::SALT as usize + BLOCK_SIZE as usize]
        .try_into()
        .unwrap();

    let mut offset: usize = 0;
    let mut peers: Vec<types::Peer> = Vec::with_capacity(1); // at least one client

    let key: [u8; 32] = match password {
        Some(p) => shared::crypto::derive_key_from_password(p.as_bytes(), &salt),
        None => [0; 32],
    };
    #[cfg(debug_assertions)]
    eprintln!(
        "key: {}",
        key.iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>()
    );

    while num_of_clients != 0 {
        let sock_addr_len: u8 = buf[GetResponseDataPositions::CLIENTS as usize + offset];
        let mut iv: [u8; BLOCK_SIZE as usize] = [0; BLOCK_SIZE as usize];
        let sock_addr_raw: Box<[u8]> =
            buf[GetResponseDataPositions::CLIENTS as usize + 1 + offset + BLOCK_SIZE as usize
                ..GetResponseDataPositions::CLIENTS as usize
                    + 1
                    + offset
                    + BLOCK_SIZE as usize
                    + sock_addr_len as usize]
                .to_vec()
                .into_boxed_slice();

        loop {
            // loop used to easily skip peer
            let peer: SocketAddr = if encrypted {
                iv.copy_from_slice(
                    &buf[GetResponseDataPositions::CLIENTS as usize + 1 + offset
                        ..GetResponseDataPositions::CLIENTS as usize
                            + 1
                            + offset
                            + BLOCK_SIZE as usize],
                );
                #[cfg(debug_assertions)]
                eprintln!(
                    "IV: {}\nSockAddr: {}",
                    iv.iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
                    sock_addr_raw
                        .iter()
                        .map(|x| format!("{:02X} ", x))
                        .collect::<String>(),
                );
                match SocketAddr::from_str(&{
                    // sacrificed a goat to borrow checker to make this work
                    let decrypted = match shared::crypto::decrypt(&key, &iv, &sock_addr_raw) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Warning peer ignored due to invalid data\nError: {}", e);
                            break;
                        }
                    };

                    match std::str::from_utf8(decrypted.as_slice()) {
                        Ok(s) => s.to_string(),
                        Err(e) => {
                            eprint!("id to utf-8 failed: {}", e);
                            eprintln!("Warning peer ignored due to invalid data");
                            break;
                        }
                    }
                }) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Warning peer ignored due to invalid data\nError: {}", e);
                        break;
                    }
                }
            } else {
                match SocketAddr::from_str(&match std::str::from_utf8(&sock_addr_raw) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        eprint!("id to utf-8 failed: {}", e);
                        eprintln!("Warning peer ignored due to invalid data");
                        break;
                    }
                }) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Warning peer ignored due to invalid data\nError: {}", e);
                        break;
                    }
                }
            };

            peers.push(types::Peer::new(peer, None));
            break;
        }
        offset += BLOCK_SIZE as usize + sock_addr_len as usize + 1 /*for size byte */;
        num_of_clients -= 1;
    }

    return Ok(types::Network::new(
        encrypted,
        key,
        network_id.to_string(),
        salt,
        peers,
    ));
}

pub fn send_heartbeat(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
    network: &types::Network,
    my_public_sock_addr: &Box<[u8]>,
    iv: &[u8; BLOCK_SIZE as usize],
) -> Result<usize, ServerErrorResponses> {
    #[cfg(debug_assertions)]
    println!("HEARTBEAT method");
    let mut send_buf: Box<[u8]> = vec![
        0u8;
        HeartBeatRequestDataPositions::IV as usize
            + BLOCK_SIZE as usize
            + my_public_sock_addr.len()
            + network.net_id.len()
    ]
    .into_boxed_slice();

    send_buf[0] = ServerMethods::HEARTBEAT as u8;
    send_buf[HeartBeatRequestDataPositions::ID_LEN as usize] = network.net_id.len() as u8;
    send_buf[HeartBeatRequestDataPositions::SOCKADDR_LEN as usize] =
        my_public_sock_addr.len() as u8;

    send_buf[HeartBeatRequestDataPositions::IV as usize
        ..HeartBeatRequestDataPositions::IV as usize + BLOCK_SIZE as usize]
        .copy_from_slice(iv);

    send_buf[HeartBeatRequestDataPositions::DATA as usize
        ..HeartBeatRequestDataPositions::DATA as usize + network.net_id.len()]
        .copy_from_slice(network.net_id.as_bytes());

    send_buf[HeartBeatRequestDataPositions::DATA as usize + network.net_id.len()
        ..HeartBeatRequestDataPositions::DATA as usize
            + network.net_id.len()
            + my_public_sock_addr.len()]
        .copy_from_slice(&my_public_sock_addr);

    #[cfg(debug_assertions)]
    eprintln!(
        "IV: {}\nSockAddr: {}",
        iv.iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
        my_public_sock_addr
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
    );

    match send_and_recv_with_retry(buf, &send_buf, dst, socket, STANDARD_RETRY_MAX) {
        Ok((data_lenght, _)) => return Ok(data_lenght),
        Err(e) => return Err(e),
    }
}

#[allow(non_snake_case)]
pub fn P2P_query(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
    encrypted: bool, // avoid deadlock
    key: [u8; 32],
) -> Result<std::net::Ipv4Addr, Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    println!("P2P QUERY method");

    let (data_lenght, _) = send_and_recv_with_retry(
        buf,
        &[P2PMethods::PEER_QUERY as u8],
        dst,
        socket,
        STANDARD_RETRY_MAX,
    )?;

    let iv: [u8; BLOCK_SIZE] = buf
        [P2PStandardDataPositions::IV as usize..P2PStandardDataPositions::IV as usize + BLOCK_SIZE]
        .try_into()
        .expect("this should never happen");

    let tmp_decrypted: Vec<u8>;

    return Ok(std::net::Ipv4Addr::from_str(if encrypted {
        match shared::crypto::decrypt(
            &key,
            &iv,
            &buf[P2PStandardDataPositions::DATA as usize..data_lenght - 1],
        ) {
            Ok(decrypted) => {
                tmp_decrypted = decrypted;
                match std::str::from_utf8(&tmp_decrypted) {
                    Ok(s) => s,
                    Err(e) => return Err(Box::new(e)),
                }
            }
            Err(e) => {
                return Err(Box::new(ServerErrorResponses::GENERAL_ERROR(format!(
                    "{}",
                    e
                ))));
            }
        }
    } else {
        match std::str::from_utf8(&buf[P2PStandardDataPositions::DATA as usize..data_lenght - 1]) {
            Ok(s) => s,
            Err(e) => return Err(Box::new(e)),
        }
    })?);
}

#[allow(non_snake_case)]
pub fn P2P_hello(
    buf: &mut [u8; UDP_BUFFER_SIZE],
    dst: &SocketAddr,
    socket: &UdpSocket,
    private_ip: Ipv4Addr,
    encrypted: bool, // avoid deadlock
    key: [u8; 32],
) -> Result<usize, ServerErrorResponses> {
    let private_ip_str = private_ip.to_string();
    let (private_ip_final, iv) = if encrypted {
        let mut rng = rng();
        let mut iv: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut iv);
        (
            shared::crypto::encrypt(&key, &iv, &private_ip_str.as_bytes())
                .unwrap()
                .into_boxed_slice(),
            iv,
        )
    } else {
        (
            private_ip_str.as_bytes().to_vec().into_boxed_slice(),
            [0u8; BLOCK_SIZE],
        )
    };

    let mut send_buf: Box<[u8]> =
        vec![0u8; P2PStandardDataPositions::DATA as usize + private_ip_final.len()].into();

    #[cfg(debug_assertions)]
    eprintln!(
        "registering network:\niv: {}\nIP: {}",
        iv.iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
        private_ip_final
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
    );

    send_buf[0] = P2PMethods::PEER_HELLO as u8;
    send_buf
        [P2PStandardDataPositions::IV as usize..P2PStandardDataPositions::IV as usize + BLOCK_SIZE]
        .copy_from_slice(&iv);

    send_buf[P2PStandardDataPositions::DATA as usize..].copy_from_slice(&private_ip_final);

    match send_and_recv_with_retry(buf, &send_buf, dst, socket, STANDARD_RETRY_MAX) {
        Ok((data_lenght, _)) => return Ok(data_lenght),
        Err(e) => return Err(e),
    }
}

pub async fn handle_incoming_connection(
    buf: [u8; UDP_BUFFER_SIZE],
    src: SocketAddr,
    network: Arc<RwLock<types::Network>>,
    tun_iface: Arc<tappers::Tun>,
    socket: Arc<std::net::UdpSocket>,
    data_lenght: usize,
) {
    #[cfg(debug_assertions)]
    eprintln!("recived method 0x{:02x}", buf[0]);
    match buf[0] {
        x if x == P2PMethods::PACKET as u8 => {
            #[cfg(debug_assertions)]
            println!("PACKET from different peer receved");

            if network.read().unwrap().encrypted {
                match shared::crypto::decrypt(
                    &network.read().unwrap().key,
                    &buf[P2PStandardDataPositions::IV as usize
                        ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE],
                    &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize],
                ) {
                    Ok(data) => match tun_iface.send(&data) {
                        Ok(_) => {}
                        Err(e) => eprintln!(
                            "{} failed to write packet to tun interface, Error: {}",
                            "[WARNING]".yellow(),
                            e
                        ),
                    },
                    Err(e) => eprintln!(
                        "{} failed to decrypt packet, Error: {}",
                        "[WARNING]".yellow(),
                        e
                    ),
                }
            } else {
                match tun_iface.send(&buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize]) {
                    Ok(_) => {},
                    Err(e) => eprintln!("{} failed to write packet to tun interface, Error: {}", "[WARNING]".yellow(), e),
                };
            }
        }
        x if x == P2PMethods::PEER_QUERY as u8 => {
            let encrypted = network.read().unwrap().encrypted;
            let private_ip = network.read().unwrap().private_ip;
            let private_ip_str = private_ip.to_string();
            let mut send_buf: Box<[u8]> = if encrypted {
                vec![
                    0;
                    P2PStandardDataPositions::DATA as usize
                        + 1
                        + (private_ip_str.len()
                            + (BLOCK_SIZE - (private_ip_str.len() % BLOCK_SIZE)))
                ]
                .into() // calculate lenght of data with block alligment
            } else {
                vec![0; P2PStandardDataPositions::DATA as usize + 1 + private_ip_str.len()].into()
            };

            send_buf[0] = P2PMethods::PEER_QUERY as u8;
            let mut iv = [0u8; BLOCK_SIZE];
            if encrypted {
                let mut rng = rng();
                rng.fill_bytes(&mut iv);
                send_buf[P2PStandardDataPositions::IV as usize
                    ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE]
                    .copy_from_slice(&iv);
                send_buf[P2PStandardDataPositions::DATA as usize
                    ..P2PStandardDataPositions::DATA as usize
                        + (private_ip_str.len()
                            + (BLOCK_SIZE - (private_ip_str.len() % BLOCK_SIZE)))]
                    .copy_from_slice(
                        shared::crypto::encrypt(
                            &network.read().unwrap().key,
                            &iv,
                            private_ip_str.as_bytes(),
                        )
                        .unwrap()
                        .as_slice(),
                    );
            } else {
                send_buf[P2PStandardDataPositions::DATA as usize
                    ..P2PStandardDataPositions::DATA as usize + private_ip_str.len()]
                    .copy_from_slice(private_ip_str.as_bytes());
            }
            match socket.send_to(&send_buf, &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            }
        }
        x if x == P2PMethods::PEER_HELLO as u8 => {
            println!("{} peer hello receved from: {}", "[LOG]".blue(), src);

            if data_lenght - 1 < P2PStandardDataPositions::DATA as usize {
                eprintln!("{} peer hello packet too small", "[ERROR]".red());
                return;
            }

            let tmp_data: Vec<u8>;
            {
                let mut network_write_lock = network.write().unwrap();
                let key: [u8; 32] = network_write_lock.key;
                let encrypted: bool = network_write_lock.encrypted;
                #[cfg(debug_assertions)]
                eprintln!(
        "registering network:\niv: {}\nIP: {}",
        &buf[P2PStandardDataPositions::IV as usize
                        ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE].iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
        &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize-1 /*compensate for size and index diference*/]
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
    );
                network_write_lock.peers.push(types::Peer::new(
                src,
                Some(
                    match std::net::Ipv4Addr::from_str(
                        match std::str::from_utf8(if encrypted {
                            match shared::crypto::decrypt(&key, &buf[P2PStandardDataPositions::IV as usize
                        ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE], &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize]) {
                                Ok(data) => {tmp_data = data; &tmp_data},
                                Err(e) => {
                                eprintln!(
                                    "{} failed to decrypt ip from peer, ignoring it Error: {}",
                                    "[WARNING]".yellow(),
                                    e
                                );
                                return;
                            },
                            }
                        } else {
                            &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize]
                        }) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!(
                                    "{} failed to parse ip from peer, ignoring it Error: {}",
                                    "[WARNING]".yellow(),
                                    e
                                );
                                return;
                            }
                        },
                    ) {
                        Ok(ip) => ip,
                        Err(e) => {
                            eprintln!(
                                "{} failed to parse ip from peer, ignoring it Error: {}",
                                "[WARNING]".yellow(),
                                e
                            );
                            return;
                        }
                    },
                ),
            ));
            }
            match socket.send_to(&[P2PMethods::PEER_HELLO as u8], &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            }
        }
        x if x == P2PMethods::PEER_GOODBYE as u8 => {
            println!("{} peer goodbye receved from: {}", "[LOG]".blue(), src);

            let mut network_lock = network.write().unwrap();

            let key = network_lock.key;
            let encrypted: bool = network_lock.encrypted;

            let mut data_tmp: Vec<u8> = Vec::with_capacity(BLOCK_SIZE); // block size

            network_lock.peers.retain(|peer| !{peer.private_ip == match std::net::Ipv4Addr::from_str(match std::str::from_utf8( if encrypted {
                match shared::crypto::decrypt(&key, &buf[P2PStandardDataPositions::IV as usize..P2PStandardDataPositions::IV as usize + BLOCK_SIZE], &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize-1 /*compensate for size and index diference*/]) {
                    Ok(data) => {data_tmp = data;
                                             &data_tmp},
                    Err(e) => {eprintln!("{} error parsing ip, Error: {}", "[ERROR]".red(), e); return false;},
                }
            } else {&buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize-1 /*compensate for size and index diference*/]}) {
                    Ok(s) => s,
                    Err(e) => {eprintln!("{} error parsing ip, Error: {}", "[ERROR]".red(), e); return false;},
                }) {
                    Ok(ip) => ip,
                    Err(e) => {eprintln!("{} error parsing ip, Error: {}", "[ERROR]".red(), e); return false;},
                } && peer.sock_addr == src});
            match socket.send_to(&[P2PMethods::PEER_GOODBYE as u8], &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            }
        }
        x if x == P2PMethods::NEW_CLIENT_NOTIFY as u8 => {
            println!(
                "{} Notified about new client, creating NAT mapping",
                "[LOG]".blue()
            );

            #[cfg(debug_assertions)]
            eprintln!(
            "registering network:\niv: {}\nsockaddr: {}",
            &buf[P2PStandardDataPositions::IV as usize
                            ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE].iter().map(|x| format!("{:02X} ", x)).collect::<String>(),
        &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize-1 /*compensate for size and index diference*/]
            .iter()
            .map(|x| format!("{:02X} ", x))
            .collect::<String>(),
    );

            let data_tmp: Box<[u8]>;
            let peer_addr: std::net::SocketAddr = match std::net::SocketAddr::from_str(
                match std::str::from_utf8(if network.read().unwrap().encrypted {
                    match shared::crypto::decrypt(
                        &network.read().unwrap().key,
                        &buf[P2PStandardDataPositions::IV as usize
                            ..P2PStandardDataPositions::IV as usize + BLOCK_SIZE],
                        &buf[P2PStandardDataPositions::DATA as usize..data_lenght as usize /*compensate for size and index diference*/],
                    ) {
                        Ok(v) => {
                            data_tmp = v.into_boxed_slice();
                            &data_tmp
                        }
                        Err(e) => {
                            eprintln!(
                                "{} failed to decrypt sock addr of new client connection not posible Error: {}",
                                "[ERROR]".red(),
                                e
                            );
                            return;
                        }
                    }
                } else {
                    &buf[P2PStandardDataPositions::DATA as usize..]
                }) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "{} failed to decode sock addr of new client connection not posible Error: {}",
                            "[ERROR]".red(),
                            e
                        );
                        return;
                    }
                },
            ) {
                Ok(sa) => sa,
                Err(e) => {
                    eprintln!(
                        "{} failed to parse sock addr of new client connection not posible Error: {}",
                        "[ERROR]".red(),
                        e
                    );
                    return;
                }
            };
            for _ in 0..MAPPING_SHOT_COUNT {
                match socket.send_to(&[P2PMethods::DO_NOTHING as u8], peer_addr) {
                    Ok(s) => {
                        #[cfg(debug_assertions)]
                        eprintln!("send {} bytes", s);
                    }
                    Err(e) => eprintln!("{} failed to send puching packet: {}", "[ERROR]".red(), e),
                }
            }
        }
        x if x == P2PMethods::DO_NOTHING as u8 => {
            println!(
                "{} punching succesful DO_NOTHING receved",
                "[SUCCESS]".green()
            );
        }
        _ => {
            eprintln!(
                "{} unknown method ID: 0x{:02x}, Droping!",
                "[WARNING]".bright_yellow(),
                buf[0]
            )
        }
    }
}

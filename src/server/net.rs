use crate::utils::send_general_error_to_client;

use super::types;
use super::utils;
use orx_concurrent_vec::ConcurrentVec;
use pea_2_pea::*;
use rayon::prelude::*;

use std::sync::Arc;
use std::u8;
pub async fn handle_request(
    buf: [u8; BUFFER_SIZE],
    socket: std::sync::Arc<std::net::UdpSocket>,
    src: core::net::SocketAddr,
    data_len: usize,
    registration_vector: Arc<ConcurrentVec<types::Registration>>,
) {
    match buf[0] {
        x if x == ServerMethods::QUERY as u8 => {
            #[cfg(debug_assertions)]
            eprintln!("QUERY method");

            let client_sock_addr_str: String = src.to_string();
            let mut send_vec: Vec<u8> = client_sock_addr_str.into();
            send_vec.insert(0, ServerMethods::QUERY as u8);

            match socket.send_to(&send_vec, &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error snding data: {}", e);
                }
            }
        }

        x if x == ServerMethods::GET as u8 => {
            #[cfg(debug_assertions)]
            println!("GET method");

            if data_len > u8::MAX as usize + 1 {
                send_general_error_to_client(
                    src,
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Network ID is too long"),
                    socket,
                );
                return; // drop packet if id lenght is biger than posible
            }

            let net_id: String = match std::str::from_utf8(&buf[1..]) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    eprint!("id to utf-8 failed: {}", e);
                    utils::send_general_error_to_client(src, e, socket);
                    return;
                }
            };

            let registration = match registration_vector
                .iter()
                .find(|elem| elem.map(|s| &s.net_id == &net_id)) // find if id exists
            {
                Some(registration) => registration,
                None => {match socket.send_to(&[ServerResponse::ID_DOESNT_EXIST as u8], src){
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error snding data: {}", e);
                }
            };
                    return;
                },
            }
            .cloned();
            let mut send_vec: Vec<u8> = Vec::with_capacity(
                1/*initial status byte */ +
                GetResponseDataPositions::SALT as usize + /*2 times one for SALT and other for first IV*/ 2*SALT_AND_IV_SIZE as usize + 20, /*magic number guess for how long is encrypted residencial ipv4 with port long */
            ); // use vector to handle many clients

            send_vec.push(ServerMethods::GET as u8); // this means success

            // lets start serializing
            send_vec.push(registration.encrypted as u8);
            send_vec.push(registration.net_id.len() as u8);
            send_vec.push(registration.clients.len() as u8);
            // todo!("make sure it allows only 255 client per network max");
            send_vec.extend_from_slice(&registration.salt);

            registration.clients.iter().for_each(|client| {
                let sock_addr_len: u8 = client.client_sock_addr.len() as u8;

                send_vec.push(sock_addr_len);

                send_vec.extend_from_slice(&client.iv);

                send_vec.extend_from_slice(&client.client_sock_addr);
            });

            if send_vec.len() > BUFFER_SIZE {
                send_general_error_to_client(
                    src,
                    std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        format!(
                            "Max number of clients reached count: {}",
                            registration.clients.len()
                        ),
                    ),
                    socket,
                );
                return;
            }

            match socket.send_to(&send_vec, &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error snding data: {}", e);
                }
            }
        }
        x if x == ServerMethods::REGISTER as u8 => {
            #[cfg(debug_assertions)]
            println!("REGISTER method");
            let encrypted: bool = buf[RegisterRequestDataPositions::ENCRYPTED as usize] != 0;

            //read lenght of sockaddr
            // rustc be like RUST HAS NO TERNARY OPERATON USE if-else
            let len_id: u8 = if buf[RegisterRequestDataPositions::ID_LEN as usize] != 0 {
                buf[RegisterRequestDataPositions::ID_LEN as usize]
            } else {
                return;
            };

            let sock_addr_len: u8 = if buf[RegisterRequestDataPositions::SOCKADDR_LEN as usize] != 0
            {
                buf[RegisterRequestDataPositions::SOCKADDR_LEN as usize]
            } else {
                return;
            };

            let net_id: String = match std::str::from_utf8(
                &buf[(RegisterRequestDataPositions::DATA as usize)
                    ..(len_id as usize) + (RegisterRequestDataPositions::DATA as usize)],
            ) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    eprint!("id to utf-8 failed: {}", e);
                    utils::send_general_error_to_client(src, e, socket);
                    return;
                }
            };

            match registration_vector
                .iter()
                .find(|elem| elem.map(|s| &s.net_id == &net_id)) // find if id exists
            {
                Some(_) => {
                    match socket.send_to(&[ServerResponse::ID_EXISTS as u8], src) {
                        Ok(s) => {
                            #[cfg(debug_assertions)]
                            eprintln!("send {} bytes", s);
                        }
                        Err(e) => {
                            eprintln!("Error sending data: {}", e);
                        }
                    };
                    return;
                }
                None => {}
            }

            let salt: Option<[u8; SALT_AND_IV_SIZE as usize]>;
            let iv: Option<[u8; SALT_AND_IV_SIZE as usize]>;

            if encrypted {
                salt = Some(
                    buf[(RegisterRequestDataPositions::SALT as usize)
                        ..(RegisterRequestDataPositions::SALT as usize)
                            + (SALT_AND_IV_SIZE as usize)]
                        .try_into()
                        .expect("this should never happen"),
                );
                iv = Some(
                    buf[(RegisterRequestDataPositions::IV as usize)
                        ..(RegisterRequestDataPositions::IV as usize)
                            + (SALT_AND_IV_SIZE as usize)]
                        .try_into()
                        .expect("this should never happen"),
                )
            } else {
                salt = None;
                iv = None;
            }

            registration_vector.push(types::Registration::new(
                net_id,
                buf[(RegisterRequestDataPositions::DATA as usize)
                    ..(RegisterRequestDataPositions::DATA as usize) + (sock_addr_len as usize)]
                    .to_vec(),
                encrypted,
                chrono::Utc::now().timestamp(),
                salt,
                iv,
            ));
            match socket.send_to(&[ServerMethods::REGISTER as u8], src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            }
            #[cfg(debug_assertions)]
            println!("network registered");
        }

        x if x == ServerMethods::HEARTBEAT as u8 => {
            #[cfg(debug_assertions)]
            println!("HEARTBEAT method");

            let id_len: u8 = if buf[HeartBeatRequestDataPositions::ID_LEN as usize] != 0 {
                buf[HeartBeatRequestDataPositions::ID_LEN as usize]
            } else {
                send_general_error_to_client(
                    src,
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "ID too short!"),
                    socket,
                );
                return;
            };
            let sock_addr_len: u8 = if buf[HeartBeatRequestDataPositions::SOCKADDR_LEN as usize]
                != 0
            {
                buf[HeartBeatRequestDataPositions::SOCKADDR_LEN as usize]
            } else {
                send_general_error_to_client(
                    src,
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "SockAddr too short!"),
                    socket,
                );
                return;
            };

            let net_id: String = match std::str::from_utf8(
                &buf[(HeartBeatRequestDataPositions::DATA as usize)
                    ..(id_len as usize) + (HeartBeatRequestDataPositions::DATA as usize)],
            ) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    eprint!("id to utf-8 failed: {}", e);
                    utils::send_general_error_to_client(src, e, socket);
                    return;
                }
            };

            let iv: [u8; SALT_AND_IV_SIZE as usize] =
                buf[HeartBeatRequestDataPositions::IV as usize
                    ..HeartBeatRequestDataPositions::IV as usize + SALT_AND_IV_SIZE as usize]
                    .try_into()
                    .unwrap();

            let sock_addr: Vec<u8> = buf[HeartBeatRequestDataPositions::DATA as usize
                + id_len as usize
                ..HeartBeatRequestDataPositions::DATA as usize
                    + id_len as usize
                    + sock_addr_len as usize]
                .to_vec();

            match registration_vector
                .iter()
                .find(|elem| elem.map(|s| &s.net_id == &net_id)) // find if id exists
            {
                Some(reg) => {
                    let current_time = chrono::Utc::now().timestamp();
                    reg.update(|r| {r.last_heart_beat = current_time;
                    match r.clients.par_iter_mut().find_first(|c| *c.client_sock_addr == *sock_addr && c.iv == iv) {
                        Some(c) => c.last_heart_beat = current_time,
                        None => {// add new client if it isn't found
                            r.clients.push(types::Client::new(sock_addr.clone(), current_time, iv));
                        }
                    };
                });
                }
                None => {match socket.send_to(&[ServerResponse::ID_DOESNT_EXIST as u8], src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            } return;}
            }
            match socket.send_to(&[ServerMethods::HEARTBEAT as u8], src) {
                // succes responce
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error sending data: {}", e);
                }
            }
            return;
        }
        _ => {
            println!(
                "Warning!: client: {} called Unknown method: 0x{:02x}",
                src.to_string(),
                buf[0]
            );
            return;
        }
    }
}

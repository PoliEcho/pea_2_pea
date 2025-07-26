use super::types;
use super::utils;
use orx_concurrent_vec::ConcurrentVec;
use pea_2_pea::*;

use std::sync::Arc;
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

            registration_vector.push(types::Registration::new(
                match std::str::from_utf8(
                    &buf[(RegisterRequestDataPositions::DATA as usize)
                        ..(len_id as usize) + (RegisterRequestDataPositions::DATA as usize)],
                ) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        eprint!("id to utf-8 failed: {}", e);
                        utils::send_general_error_to_client(src, e, socket);
                        return;
                    }
                },
                buf[(len_id as usize) + (RegisterRequestDataPositions::DATA as usize)
                    ..(len_id as usize)
                        + (RegisterRequestDataPositions::DATA as usize)
                        + (sock_addr_len as usize)]
                    .to_vec(),
                encrypted,
                chrono::Utc::now().timestamp(),
            ));
        }

        x if x == ServerMethods::HEARTBEAT as u8 => {
            #[cfg(debug_assertions)]
            println!("HEARTBEAT method");
        }
        _ => {
            #[cfg(debug_assertions)]
            println!("Unknown method");
            return;
        }
    }
}

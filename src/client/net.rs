use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
};

use pea_2_pea::*;
use rand::RngCore;

// return data_lenght and number of retryes
pub fn send_and_recv_with_retry(
    buf: &mut [u8; BUFFER_SIZE],
    dst: &SocketAddr,
    socket: UdpSocket,
    retry_max: usize,
) -> Result<(usize, usize), ServerErrorResponses> {
    let mut send_buf = *buf;
    let mut retry_count: usize = 0;
    loop {
        match socket.send_to(&mut send_buf, dst) {
            Ok(s) => {
                #[cfg(debug_assertions)]
                eprintln!("send {} bytes", s);
            }
            Err(e) => {
                panic!("Error sending data: {}", e);
            }
        }

        match socket.recv_from(buf) {
            Ok((data_lenght, src)) => {
                if src != *dst {
                    continue;
                }
                match buf[0] {
                    x if x == send_buf[0] as u8 => {
                        return Ok((data_lenght, retry_count));
                    }
                    x if x == ServerResponse::GENERAL_ERROR as u8 => {
                        return Err(ServerErrorResponses::IO(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            match std::str::from_utf8(&buf[1..data_lenght]) {
                                // the firts byte is compensated for sice this is len not index
                                Ok(s) => s.to_string(),
                                Err(e) => format!("invalid error string: {}", e).to_string(),
                            },
                        )));
                    }
                    x if x == ServerResponse::ID_DOESNT_EXIST as u8 => {
                        return Err(ServerErrorResponses::ID_DOESNT_EXIST);
                    }
                    x if x == ServerResponse::ID_EXISTS as u8 => {
                        return Err(ServerErrorResponses::ID_EXISTS);
                    }
                    _ => {
                        continue;
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // timedout
                if retry_count >= retry_max {
                    return Err(ServerErrorResponses::IO(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "max retry count reached without responce",
                    )));
                }
                retry_count += 1;
                continue;
            }
            Err(e) => {
                return Err(ServerErrorResponses::IO(e));
            }
        }
    }
}

pub fn query_request(
    buf: &mut [u8; BUFFER_SIZE],
    dst: &SocketAddr,
    socket: UdpSocket,
) -> Result<usize, ServerErrorResponses> {
    match send_and_recv_with_retry(buf, dst, socket, STANDARD_RETRY_MAX) {
        Ok((data_lenght, _)) => return Ok(data_lenght),
        Err(e) => return Err(e),
    }
}

pub fn register_request(
    buf: &mut [u8; BUFFER_SIZE],
    dst: &SocketAddr,
    socket: UdpSocket,
    encryption_key: Option<[u8; 32]>,
    salt_opt: Option<[u8; SALT_AND_IV_SIZE as usize]>,
    mut public_sock_addr: Vec<u8>,
    network_id: String,
) -> Result<usize, ServerErrorResponses> {
    buf[0] = ServerMethods::REGISTER as u8; // set metod identification byte
    buf[RegisterRequestDataPositions::ENCRYPTED as usize] = match encryption_key {
        // stor encryption flag byte
        Some(_) => true as u8,
        None => false as u8,
    };
    buf[RegisterRequestDataPositions::ID_LEN as usize] = network_id.len() as u8;

    buf[RegisterRequestDataPositions::DATA as usize
        ..RegisterRequestDataPositions::DATA as usize + network_id.len()]
        .copy_from_slice(network_id.as_bytes()); // store network id

    let mut iv: [u8; SALT_AND_IV_SIZE as usize] = [0; SALT_AND_IV_SIZE as usize];
    let salt: [u8; SALT_AND_IV_SIZE as usize];
    match salt_opt {
        Some(s) => salt = s,
        None => salt = [0; SALT_AND_IV_SIZE as usize],
    }
    match encryption_key {
        Some(encryption_key) => {
            let mut rng = rand::rng();
            rng.fill_bytes(&mut iv);
            public_sock_addr =
                shared::crypto::encrypt(&encryption_key, &iv, public_sock_addr.as_slice()).unwrap();
        }
        None => {
            iv = [0; SALT_AND_IV_SIZE as usize];
        }
    };

    buf[RegisterRequestDataPositions::IV as usize
        ..RegisterRequestDataPositions::IV as usize + SALT_AND_IV_SIZE as usize]
        .copy_from_slice(&iv); // copy iv ad salt do the request
    buf[RegisterRequestDataPositions::SALT as usize
        ..RegisterRequestDataPositions::SALT as usize + SALT_AND_IV_SIZE as usize]
        .copy_from_slice(&salt);

    buf[RegisterRequestDataPositions::SOCKADDR_LEN as usize] = public_sock_addr.len() as u8;

    buf[RegisterRequestDataPositions::DATA as usize + network_id.len()
        ..RegisterRequestDataPositions::DATA as usize + network_id.len() + public_sock_addr.len()]
        .copy_from_slice(&public_sock_addr);

    match send_and_recv_with_retry(buf, dst, socket, STANDARD_RETRY_MAX) {
        Ok((data_lenght, _)) => return Ok(data_lenght),
        Err(e) => return Err(e),
    }
}

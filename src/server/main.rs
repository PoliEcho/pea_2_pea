mod net;
mod types;
mod utils;
use smol::net::UdpSocket;
use std::{process::exit, sync::Arc};

use orx_concurrent_vec::ConcurrentVec;
fn main() -> std::io::Result<()> {
    {
        let socket: Arc<UdpSocket> = Arc::new(
            smol::block_on(async {
                let listen_port: u16 = pea_2_pea::SERVER_PORT;
                UdpSocket::bind(format!("0.0.0.0:{}", listen_port)).await
            })
            .expect("Failed to bind to any available port"),
        );

        let registration_vector: Arc<ConcurrentVec<types::Registration>> =
            Arc::new(orx_concurrent_vec::ConcurrentVec::new());

        {
            let reg_clone = registration_vector.clone();
            std::thread::spawn(move || {
                utils::disconnected_cleaner(reg_clone);
            });
        }

        let mut buf: [u8; pea_2_pea::UDP_BUFFER_SIZE] = [0u8; pea_2_pea::UDP_BUFFER_SIZE];
        smol::block_on(async {
            loop {
                buf.fill(0);
                match socket.recv_from(&mut buf).await {
                    Ok((data_length, src)) => {
                        smol::spawn(net::handle_request(
                            buf,
                            socket.clone(),
                            src,
                            data_length,
                            registration_vector.clone(),
                        ))
                        .detach();
                    }
                    Err(e) => {
                        eprintln!("Error receiving data: {}", e);
                        exit(-4);
                    }
                }
            }
        });

        // socket.send_to(&buf, &src)?;
    } // the socket is closed here
    Ok(())
}

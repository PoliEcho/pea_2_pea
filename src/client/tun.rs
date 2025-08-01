use std::sync::{Arc, RwLock};

use pea_2_pea::*;
use rand::RngCore;
use rayon::prelude::*;

use crate::types::Network;

pub fn create_tun_interface(
    private_ip: std::net::Ipv4Addr,
    if_name: Option<String>,
) -> Result<tappers::Tun, std::io::Error> {
    let mut tun_iface: tappers::Tun = tappers::Tun::new_named(tappers::Interface::new(
        if_name.unwrap_or("pea0".to_owned()),
    )?)?;
    let mut addr_req = tappers::AddAddressV4::new(private_ip);
    addr_req.set_netmask(24);
    let mut broadcast_addr_oct = private_ip.octets();
    broadcast_addr_oct[3] = 255;
    addr_req.set_broadcast(std::net::Ipv4Addr::from(broadcast_addr_oct));
    tun_iface.add_addr(addr_req)?;
    tun_iface.set_up()?;
    return Ok(tun_iface);
}

pub fn read_tun_iface(
    tun_iface: Arc<tappers::Tun>,
    socket: Arc<std::net::UdpSocket>,
    network: Arc<RwLock<Network>>,
) {
    let mut buf: [u8; IP_BUFFER_SIZE] = [0u8; IP_BUFFER_SIZE];

        smol::block_on(async {
        loop {
             #[cfg(debug_assertions)]
            eprintln!("Started listening for ip packets");
            let data_lenght = tun_iface.recv(&mut buf).unwrap(); // build in auto termination, isn't it great
            smol::spawn(handle_ip_packet(
                buf[..data_lenght - 1].to_vec().into(),
                network.clone(),
                socket.clone(),
            ))
            .detach();
        }});
    
}

pub async fn handle_ip_packet(
    packet_data: Box<[u8]>,
    network: Arc<RwLock<Network>>,
    socket: Arc<std::net::UdpSocket>,
) {
    #[cfg(debug_assertions)]
            eprintln!("Processing IP packet");
    let dst_ip = std::net::Ipv4Addr::from(
        match <[u8; 4]>::try_from(
            &packet_data[DEST_IN_IPV4_OFFSET..DEST_IN_IPV4_OFFSET + IPV4_SIZE],
        ) {
            Ok(slice) => slice,
            Err(e) => {
                eprintln!("Procesing of IP packet failed, Invalid dst IP: {}", e);
                return;
            }
        },
    );
    let mut rng = rand::rng();

    let mut iv: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
    rng.fill_bytes(&mut iv);

    let mut encrypted_data =
        match shared::crypto::encrypt(&network.read().unwrap().key, &iv, &packet_data) {
            Ok(cr) => cr,
            Err(e) => {
                eprintln!("Failed to encrypt packet droping it: {}", e);
                return;
            }
        };

    encrypted_data.insert(0, P2PMethods::PACKET as u8);
    encrypted_data.splice(1..1, iv);

    if dst_ip.octets()[3] == 255 {
        network.read().unwrap().peers.par_iter().for_each(|peer| {
            // broadcast
            match socket.send_to(&encrypted_data, peer.sock_addr) {
                Ok(_) => {}
                Err(e) => eprintln!("failed to send packet: {}", e),
            };
        });
    } else {
        let dst = match network
            .read()
            .unwrap()
            .peers
            .par_iter()
            .find_any(|&p| p.private_ip == dst_ip)
            .map(|p| p.sock_addr)
        {
            Some(sa) => sa,
            None => return,
        };

        match socket.send_to(&encrypted_data, dst) {
            Ok(_) => {}
            Err(e) => eprintln!("failed to send packet: {}", e),
        };
    }
}

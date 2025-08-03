# Pea 2 Pea  
very simple P2P VPN(Virtual Network yes, Private maybe),  
this program is intended to help you play LAN games over internet  
when all clients are behind Full-cone NAT, does not work with clients behind Symmetric NAT  
at least for now  

## how to run  
> install rustc and cargo or rustup, you will need 2024 edition  
> build using  
> ```bash
> # to build
> cargo build --release
> # to run server(registrar)
> ./target/release/server
> # to run client
> sudo ./target/release/client -r SERVER_IP -n NETWORK_ID -P PASSWORD # password is optional
> ```
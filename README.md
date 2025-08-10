<img src="https://git.pupes.org/PoliEcho/pea_2_pea/raw/branch/master/logo.svg" alt="Pea 2 Pea logo" width="196"></img>
# Pea 2 Pea  
very simple P2P VPN(Virtual Network yes, Private maybe),  
this program is intended to help you play LAN games over internet and as proof of concept  
when all clients are behind Full-cone NAT, does not work with clients behind Symmetric NAT  
at least for now  


> [!WARNING]  
> Piercing NAT may fail based on network configuration minor bug fixes  

> [!WARNING]    
>  windows client does not work thanks to some tappers library issues

## how to run  
> install rustc and cargo or rustup, you will need 2024 edition  
> if using windows you need to get [wintun](https://www.wintun.net/) driver  
> build using  
> ```bash
> # to build
> cargo build --release
> # to run server(registrar)
> ./target/release/server
> # to run client
> sudo ./target/release/client -r SERVER_IP -n NETWORK_ID -P PASSWORD # password is optional
> ```
from protocolVpn import KeyGenerator, VpnCipher, BUFFER
import logging
import asyncio
from TunAdapter import create_adapter, toolkit
from typing import Dict, Tuple
import socket
from mainServerProtocol import SecureSocket

SERVER_PORT = 50505
SERVER_IP = "79.177.161.218"
MASK = "/24"
ADDRESS = "10.9.0.1" + MASK
NAME = "vpn-tun"
IP_POOL = [f"10.9.0.{i}" for i in range(10, 251)]
SERVER_NAME = "node_01"

# Modified to hold the VpnCipher objects for each client
client_ciphers: Dict[Tuple[str, int], VpnCipher] = {} 
ip_to_addr_map: Dict[str, Tuple[str, int]] = {}
addr_to_ip_map = {}

# Instantly generate blazing-fast X25519 keys
SERVER_PRIVATE_KEY, SERVER_PUBLIC_BYTES = KeyGenerator.generate_x25519_keypair()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_route_table():
    logging.info("Setting up server routing table...")
    toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=1")
    toolkit.run("iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -m comment --comment 'vpn' -j MASQUERADE")  
    toolkit.run("iptables -A FORWARD -s 10.9.0.0/24 -j ACCEPT")
    toolkit.run("iptables -A FORWARD -d 10.9.0.0/24 -j ACCEPT")

def cleanup_route_table():
    logging.info("Cleaning up server routing table...")
    toolkit.run("iptables -t nat -D POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -m comment --comment 'vpn' -j MASQUERADE", check=False)
    toolkit.run("iptables -D FORWARD -s 10.9.0.0/24 -j ACCEPT", check=False)
    toolkit.run("iptables -D FORWARD -d 10.9.0.0/24 -j ACCEPT", check=False)

class ServerDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, tun_adapter):
        self.tun_adapter = tun_adapter
        self.transport = None
        self.packet_count = 0

    def connection_made(self, transport):
        self.transport = transport
        logging.info("Server UDP endpoint started.")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 4: return
        msg_code = data[:4]

        # 1. Handshake Phase
        if msg_code == b"GETK":
            client_pub_bytes = data[4:]
            aes_key = KeyGenerator.derive_aes_key(SERVER_PRIVATE_KEY, client_pub_bytes)
            client_ciphers[addr] = VpnCipher(aes_key)
            self.transport.sendto(b"KEYE" + SERVER_PUBLIC_BYTES, addr)
            logging.info(f"Secure tunnel established with {addr}")
        
        # 2. IP Assignment Phase (If your client requests one)
        elif msg_code == b"GETI":
            if addr not in client_ciphers: return
            
            # --- NEW: Check if this client already has an IP assigned ---
            if addr in addr_to_ip_map:
                ip = addr_to_ip_map[addr]
            elif IP_POOL:
                ip = IP_POOL.pop(0)
                ip_to_addr_map[ip] = addr
                addr_to_ip_map[addr] = ip
            else:
                logging.warning("No IPs left in pool!")
                return
                
            cipher = client_ciphers[addr]
            encrypted_ip = cipher.encrypt(ip.encode())
            self.transport.sendto(b"IP__" + encrypted_ip, addr)
            logging.info(f"Assigned/Confirmed IP {ip} for {addr}")

        # 3. Encrypted Data Traffic
        else:
            if addr not in client_ciphers:
                return 
                
            try:
                plaintext = client_ciphers[addr].decrypt(data) 
                
                # --- ADD THIS LOGIC TO PRINT EVERY 10th PACKET ---
                self.packet_count += 1
                if self.packet_count % 1000 == 0:
                    logging.info(f"[{addr}] Secure traffic flowing: {self.packet_count} packets received. (Latest: {len(plaintext)} bytes)")
                # -------------------------------------------------
                
                asyncio.create_task(self.write_to_tun(plaintext, addr))
                
            except ValueError:
                pass  # Silently drop network duplicates
            except Exception as e:
                logging.error(f"Decryption error from {addr}: {e}")

    async def write_to_tun(self, plaintext, addr):
        await self.tun_adapter.write(plaintext)


async def main():
    setup_route_table()
    tun_adapter = await create_adapter(ADDRESS, NAME)
    
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerDatagramProtocol(tun_adapter),
        local_addr=("0.0.0.0", SERVER_PORT)
    )

    try:
        while True:
            packet = await tun_adapter.read()
            if not packet: continue
            
            parsed_packet = toolkit.parse_packet(packet)
            dst_ip = getattr(parsed_packet, 'dst', None)
            if type(dst_ip) != str:
                 dst_ip = getattr(parsed_packet, 'dst_s', None)

            if dst_ip in ip_to_addr_map:
                addr = ip_to_addr_map[dst_ip]
                if addr in client_ciphers:
                    cipher = client_ciphers[addr]
                    encrypted_packet = cipher.encrypt(packet)
                    transport.sendto(encrypted_packet, addr)

    except asyncio.CancelledError:
        pass
        
    finally:
        if transport: transport.close()
        cleanup_route_table()
        logging.info("Server shutdown complete.")

def connect_to_server(addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(addr)
        secure = SecureSocket(sock)
        secure.client_handshake()
        
        payload = {
            "cmd": "SLGN", 
            "server_name": SERVER_NAME, 
            "port": SERVER_PORT,
            "host": SERVER_IP 
        }
        
        secure.send_json(payload)
        cmd = secure.recv_json().get("cmd")
        if cmd == "CNFM":
            print("[VPN-SERVER] successfully connected to main server")
            return secure
    except Exception as e:
        print(f"[VPN-SERVER] Connection failed: {e}")

if __name__ == "__main__":
    print("[VPN-SERVER] connecting to main server")
    # Make sure this IP matches your Broker node!
    secure = connect_to_server(("192.168.7.5", 8000)) 
    asyncio.run(main())
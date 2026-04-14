from protocol import KeyGenerator, KeySwitch, AesEncryptDecrypt, BUFFER
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

aes_keys: Dict[Tuple[str, int], bytes] = {} 
ip_to_addr_map: Dict[str, Tuple[str, int]] = {}
addr_to_ip_map = {}
KeyGenerator.generate_keys()
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = KeyGenerator.load_keys()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_route_table():
    # Enable forwarding and set up NAT/iptables rules
    logging.info("Setting up server routing table...")
    toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=1")

    toolkit.run("iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -m comment --comment 'vpn' -j MASQUERADE")  
    # sets up NAT masquerading for VPN clients so their traffic appears from the server's IP

    toolkit.run("iptables -A FORWARD -s 10.9.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT")  
    # allows forwarding of return traffic from external connections back to VPN clients

    toolkit.run("iptables -A FORWARD -d 10.9.0.0/24 -j ACCEPT")  
    # allows forwarding of incoming traffic to VPN clients
    logging.info("Routing table set up.")

def cleanup_route_table():
    # Remove forwarding and delete NAT/iptables rules
    logging.info("Restoring server routing table...")
    try:
        toolkit.run("iptables -t nat -D POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -m comment --comment 'vpn' -j MASQUERADE")
        toolkit.run("iptables -D FORWARD -s 10.9.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT")
        toolkit.run("iptables -D FORWARD -d 10.9.0.0/24 -j ACCEPT")
        toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=0")
    except Exception as e:
        logging.warning("Error during routing cleanup (rule might not have been present): %s", e)
    logging.info("Routing table restored.")



class VPNDatagramProtocol(asyncio.DatagramProtocol):
    """Handles network I/O for the VPN (UDP socket)."""
    def __init__(self, adapter):
        self.adapter = adapter
        self.transport = None
        self.msg_codes = {"GETK": self.handle_get_key, "SENK": self.handle_send_key, "GETP": self.handle_get_ip, "PCKT": self.write_to_tun, "DISC": self.handle_disconnection}
        

    def connection_made(self, transport):
        self.transport = transport
        logging.info("UDP Transport listening on port %d", SERVER_PORT)


    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if addr not in aes_keys:
            try:
                msg_code = data[:4].decode()
                args = data[4:]
                
                if msg_code in self.msg_codes.keys():
                    self.msg_codes[msg_code](args, addr)
                else:
                    logging.warning("Unknown message code %s from %s", msg_code, addr)
                    
            except Exception as e:
                logging.error("Handshake error from %s: %s", addr, e)
        else:
            try:
                aes_key = aes_keys[addr]
                msg = AesEncryptDecrypt.aes_decrypt(aes_key, data)
                msg_code = msg[:4].decode()
                args = msg[4::]

                # if msg_code in self.msg_codes.keys():
                #     self.msg_codes[msg_code](args, addr)
                # else:
                    # logging.warning("Unknown message code %s from %s", msg_code, addr)
                asyncio.create_task(self.write_to_tun(args, addr))

            except Exception as e:
                logging.error("Decryption/Write error from %s: %s", addr, e)


    def handle_get_key(self, args, addr):
        try:
            self.transport.sendto(b"KEYE" + SERVER_PUBLIC_KEY.export_key(), addr)
            logging.info("Sent server public key to %s", addr)
        except Exception as e:
            logging.error("Failed to send public key to %s: %s", addr, e)


    def handle_get_ip(self, args, addr):
        if addr in addr_to_ip_map.keys():
            return
        
        client_ip = IP_POOL.pop(0)
        ip_to_addr_map[client_ip] = addr
        addr_to_ip_map[addr] = client_ip
        try:
            self.transport.sendto(f"STIP{client_ip}{MASK}".encode(), addr)
            logging.info("Sent private ip %s to %s", client_ip,addr)
        except Exception as e:
            logging.error("Failed to send private ip to %s: %s", addr, e)


    def handle_send_key(self, args, addr):
        try:
            aes_key = KeySwitch.decrypt_aes_key(args, SERVER_PRIVATE_KEY)[4::] # Sync call
            aes_keys[addr] = aes_key
            
            client_ip = addr_to_ip_map[addr]
            
            logging.info("Client %s established with AES key. Allocated IP: %s", addr, client_ip)
            
        except Exception as e:
            logging.error("Failed to decrypt/establish AES key from %s: %s", addr, e)

    
    def handle_disconnection(self, args,addr):
        # FIX: Get the client_ip from the map BEFORE logging it!
        client_ip = addr_to_ip_map[addr]
        logging.info("Client from %s with private ip of %s disconnected", addr, client_ip)
        
        ip_to_addr_map.pop(client_ip)
        aes_keys.pop(addr)
        IP_POOL.append(client_ip)


    # def handle_packet(self, args, addr):
    #     asyncio.create_task(self.write_to_tun(args, addr))


    async def write_to_tun(self, packet: bytes, addr: Tuple[str, int]):
        """Writes a decrypted packet to the TUN adapter."""
        try:
            parsed_packet = toolkit.parse_packet(packet)
            
            if parsed_packet.src_s not in ip_to_addr_map:
                ip_to_addr_map[parsed_packet.src_s] = addr

            await self.adapter.write(packet)
            logging.debug("Wrote packet to TUN: %s -> %s", parsed_packet.src_s, parsed_packet.dst_s)
            
        except Exception as e:
            logging.error("Error writing to adapter: %s", e)



async def read_from_tun_loop(adapter, transport):
    while True:
        try:
            packet = await adapter.read() 
            parsed_packet = toolkit.parse_packet(packet)
            
            dst_ip = parsed_packet.dst_s
            
            if dst_ip in ip_to_addr_map:
                # Packet is for a connected VPN client
                addr = ip_to_addr_map[dst_ip]
                aes_key = aes_keys[addr]
                
                encrypted_packet = AesEncryptDecrypt.aes_encrypt(aes_key, b"PRSP" + packet)
                
                transport.sendto(encrypted_packet, addr)
                
                logging.debug("TUN: Encrypted and sent packet to client %s for destination %s", addr, dst_ip)
            else:
                # Packet is likely for the external internet or an unmapped destination
                logging.debug("TUN: Packet %s -> %s is for external routing/NAT or unmapped.", parsed_packet.src_s, parsed_packet.dst_s)
            
        except Exception as e:
            logging.error("Error reading from TUN: %s", e)
            

async def main():
    adapter = await create_adapter(ADDRESS, NAME)
    setup_route_table()
    
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: VPNDatagramProtocol(adapter),
        local_addr=('0.0.0.0', SERVER_PORT))

    tun_reader_task = asyncio.create_task(read_from_tun_loop(adapter, transport))
    
    try:
        await asyncio.gather(tun_reader_task) 
    
    except asyncio.CancelledError:
        pass
        
    finally:
        # Clean up resources on exit
        if transport: transport.close()
        cleanup_route_table()
        logging.info("Server shutdown complete.")


def connect_to_server(addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(addr)
        secure = SecureSocket(sock)
        secure.client_handshake()
        
        # --- ADDED: Include the manual 'host' IP in the payload ---
        payload = {
            "cmd": "SLGN", 
            "server_name": SERVER_NAME, 
            "port": SERVER_PORT,
            "host": SERVER_IP  # <--- Sending the IP manually
        }
        
        secure.send_json(payload)
        cmd = secure.recv_json().get("cmd")
        print(cmd)
        if cmd == "CNFM":
            print("[VPN-SERVER] successfully connected to main server")
            return secure
    except Exception as e:
        print(f"[VPN-SERVER] Connection failed: {e}")

if __name__ == "__main__":
    print("[VPN-SERVER] connecting to main server")
    secure = connect_to_server(("192.168.7.5", 8000))
    if secure:
            try:
                asyncio.run(main())
            except KeyboardInterrupt:
                logging.info("Server stopped by user.")
    else:
        print("[VPN-SERVER] unable to connected to the main server")
    
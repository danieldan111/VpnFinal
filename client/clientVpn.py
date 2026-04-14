from protocolVpn import KeyGenerator, VpnCipher, BUFFER
from TunAdapter import create_adapter, toolkit
import asyncio
import logging
import sys
from typing import Tuple, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ADDRESS = None
NAME = "vpn-tun"

CLIENT_ADAPTER = None
vpn_cipher = None
CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_BYTES = KeyGenerator.generate_x25519_keypair()

def setup_route_table(interface_name, server_ip_addr):
    logging.info("Setting up client routing table...")
    toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=1")
    
    old_default_route = toolkit.run("ip route show 0/0")
    if "via" in old_default_route:
        old_gateway_ip_addr = old_default_route[old_default_route.find("via") + 4: old_default_route.find("dev") - 1].strip()
        if old_gateway_ip_addr:
            toolkit.run(f"ip route add {server_ip_addr} via {old_gateway_ip_addr}")
            toolkit.run(f"ip route add 0.0.0.0/1 dev {interface_name}")
            toolkit.run(f"ip route add 128.0.0.0/1 dev {interface_name}")

def restore_routing_table(server_ip_addr):
    logging.info("Restoring client routing table...")
    toolkit.run(f"ip route del {server_ip_addr}", check=False)
    toolkit.run("ip route del 0.0.0.0/1", check=False)
    toolkit.run("ip route del 128.0.0.0/1", check=False)

class ClientVPNDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.handshake_done = False
        self.tun_started = False
        self.packet_count = 0

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(b"GETK" + CLIENT_PUBLIC_BYTES, SERVER_ADDR)
        logging.info("Sent GETK and Client Public Key to server...")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        global vpn_cipher, ADDRESS, CLIENT_ADAPTER
        
        if len(data) < 4: return
        msg_code = data[:4]

        if msg_code == b"KEYE":
            if self.handshake_done: 
                return # Ignore duplicate UDP packets!
            self.handshake_done = True
            
            server_pub_bytes = data[4:]
            aes_key = KeyGenerator.derive_aes_key(CLIENT_PRIVATE_KEY, server_pub_bytes)
            vpn_cipher = VpnCipher(aes_key)
            logging.info("Secure AES-GCM Tunnel Established!")
            
            # Ask the server for an IP in the pool
            self.transport.sendto(b"GETI", SERVER_ADDR)
            
        elif msg_code == b"IP__":
            if self.tun_started: 
                return # Ignore duplicate IP assignments!
            self.tun_started = True
            
            if vpn_cipher is None: return
            try:
                ip_bytes = vpn_cipher.decrypt(data[4:])
                ADDRESS = ip_bytes.decode() + "/24"
                logging.info(f"Received IP from server: {ADDRESS}")
                
                # We have our Key and IP. Start the TUN interface!
                self.loop.create_task(self.start_tun())
            except Exception as e:
                logging.error(f"Error decrypting IP: {e}")
                self.tun_started = False # Reset on failure

        else:
            if vpn_cipher is None or CLIENT_ADAPTER is None:
                return
            try:
                plaintext = vpn_cipher.decrypt(data)
                
                # --- ADD THIS LOGIC TO PRINT EVERY 10th PACKET ---
                self.packet_count += 1
                if self.packet_count % 1000 == 0:
                    logging.info(f"Secure traffic flowing: {self.packet_count} packets received from server.")
                # -------------------------------------------------
                
                self.loop.create_task(CLIENT_ADAPTER.write(plaintext))
            except ValueError:
                pass  # Silently ignore duplicates
            except Exception as e:
                logging.error(f"Decryption error: {e}")

    async def start_tun(self):
        global CLIENT_ADAPTER
        CLIENT_ADAPTER = await create_adapter(ADDRESS, NAME)
        setup_route_table(NAME, CLIENT_SERVER_IP_ADDR)
        self.loop.create_task(self.tun_to_server())

    async def tun_to_server(self):
        while True:
            try:
                packet = await CLIENT_ADAPTER.read()
                if not packet: continue
                
                if vpn_cipher:
                    encrypted_packet = vpn_cipher.encrypt(packet)
                    self.transport.sendto(encrypted_packet, SERVER_ADDR)
            
            # --- PREVENT INFINITE SPAM ---
            except ValueError:
                logging.error("TUN file closed. Stopping loop.")
                break 
            except Exception as e:
                logging.error("Error reading from TUN: %s", e)
                await asyncio.sleep(1)

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientVPNDatagramProtocol(loop),
        remote_addr=SERVER_ADDR) 
    
    try:
        await asyncio.Future() 
    
    except asyncio.CancelledError:
        pass
        
    finally:
        if transport: transport.close()
        restore_routing_table(CLIENT_SERVER_IP_ADDR)
        logging.info("Client shutdown complete.")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python clientVpn.py <IP> <PORT>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    SERVER_ADDR = (target_ip, target_port)
    CLIENT_SERVER_IP_ADDR = SERVER_ADDR[0]
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
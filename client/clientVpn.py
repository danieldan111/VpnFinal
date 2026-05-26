from protocolVpn import KeyGenerator, VpnCipher, BUFFER
from TunAdapter import create_adapter, toolkit
import asyncio
import logging
import sys
from typing import Tuple, Dict
import time
import os
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ADDRESS = None
NAME = "vpn-tun"

CLIENT_ADAPTER = None
vpn_cipher = None
CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_BYTES = KeyGenerator.generate_x25519_keypair()

# Persistent lifetime counters tracking total bytes processed over the socket layer
total_rx_bytes = 0
total_tx_bytes = 0

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
        self.last_seen_server = time.time()

        # Start background monitor cycles
        self.loop.create_task(self.monitor_connection())
        self.loop.create_task(self.check_ip_timeout())
        self.loop.create_task(self.report_bandwidth())

    async def check_ip_timeout(self):
        """Waits x seconds. If the IP isn't received by then, shut down."""
        IP_TIMEOUT_SECONDS = 2 
        
        await asyncio.sleep(IP_TIMEOUT_SECONDS)
        
        if not self.tun_started:
            logging.error(f"Failed to receive an IP address within {IP_TIMEOUT_SECONDS} seconds. Aborting!")
            os._exit(1)

    def connection_made(self, transport):
        self.transport = transport
        auth_data = json.dumps({"u": USERNAME, "t": TOKEN}).encode('utf-8')
        payload = b"GETK" + CLIENT_PUBLIC_BYTES + auth_data
        
        self.transport.sendto(payload, SERVER_ADDR)
        logging.info(f"Sent GETK, Public Key, and Auth Token for user '{USERNAME}'...")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        global vpn_cipher, ADDRESS, CLIENT_ADAPTER, total_rx_bytes
        
        # Accumulate the incoming raw encrypted network payload size
        total_rx_bytes += len(data)

        if len(data) < 4: return
        msg_code = data[:4]

        if msg_code == b"KEYE":
            if self.handshake_done: 
                return 
            self.handshake_done = True
            
            server_pub_bytes = data[4:]
            aes_key = KeyGenerator.derive_aes_key(CLIENT_PRIVATE_KEY, server_pub_bytes)
            vpn_cipher = VpnCipher(aes_key)
            logging.info("Secure AES-GCM Tunnel Established!")
            
            self.transport.sendto(b"GETI", SERVER_ADDR)
            
        elif msg_code == b"IP__":
            if self.tun_started: 
                return 
            self.tun_started = True
            
            if vpn_cipher is None: return
            try:
                ip_bytes = vpn_cipher.decrypt(data[4:])
                ADDRESS = ip_bytes.decode() + "/24"
                logging.info(f"Received IP from server: {ADDRESS}")
                
                self.loop.create_task(self.start_tun())
            except Exception as e:
                logging.error(f"Error decrypting IP: {e}")
                self.tun_started = False 

        else:
            if vpn_cipher is None or CLIENT_ADAPTER is None:
                return
            try:
                plaintext = vpn_cipher.decrypt(data)
                self.last_seen_server = time.time()

                self.packet_count += 1
                if self.packet_count % 1000 == 0:
                    logging.info(f"Secure traffic flowing: {self.packet_count} packets received from server.")
                
                self.loop.create_task(CLIENT_ADAPTER.write(plaintext))
            except ValueError:
                pass  
            except Exception as e:
                logging.error(f"Decryption error: {e}")

    async def start_tun(self):
        global CLIENT_ADAPTER
        CLIENT_ADAPTER = await create_adapter(ADDRESS, NAME)
        setup_route_table(NAME, CLIENT_SERVER_IP_ADDR)
        self.loop.create_task(self.tun_to_server())

    async def tun_to_server(self):
        global total_tx_bytes
        while True:
            try:
                packet = await CLIENT_ADAPTER.read()
                if not packet: continue
                
                if vpn_cipher:
                    encrypted_packet = vpn_cipher.encrypt(packet)
                    self.transport.sendto(encrypted_packet, SERVER_ADDR)
                    
                    # Accumulate TRUE network layer payload sizes after encryption processing
                    total_tx_bytes += len(encrypted_packet)
            
            except ValueError:
                logging.error("TUN file closed. Stopping loop.")
                break 
            except Exception as e:
                logging.error("Error reading from TUN: %s", e)
                await asyncio.sleep(1)
    
    async def monitor_connection(self):
        TIMEOUT_SECONDS = 20
        
        while True:
            await asyncio.sleep(10)
            
            if time.time() - self.last_seen_server > TIMEOUT_SECONDS:
                logging.error("Connection to server lost! Shutting down tunnel...")
                os._exit(1)
    
    async def report_bandwidth(self):
        global total_rx_bytes, total_tx_bytes
        while True:
            await asyncio.sleep(0.5) # Output stats twice a second for a more responsive UI
            # Streams total historical values down stdout without modifying local counters
            print(f"[STATS] {total_rx_bytes},{total_tx_bytes}", flush=True)

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
    if len(sys.argv) != 5:
        print("Usage: python clientVpn.py <IP> <PORT> <USERNAME> <TOKEN>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    USERNAME = sys.argv[3]
    TOKEN = sys.argv[4]
    SERVER_ADDR = (target_ip, target_port)
    CLIENT_SERVER_IP_ADDR = SERVER_ADDR[0]
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
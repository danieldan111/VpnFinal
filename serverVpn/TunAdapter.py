import os
from fcntl import ioctl
import struct
import subprocess
import logging
import aiofiles
import asyncio
from pypacker.layer3.ip import IP as IPv4Packet
from pypacker.layer3.ip6 import IP6 as IPv6Packet
from pypacker.layer3 import ip
from typing import Union, Callable


logging.basicConfig(level=logging.DEBUG)
MTU = 1420
#IOCTL Constants:
#dir\size\type\number
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # No packet information


class toolkit:
    @staticmethod
    def run(cmd):
        logging.debug("Running: %s", cmd)
        return subprocess.check_output(cmd.split()).decode()


    @staticmethod
    def packet_version(packet: bytes) -> int:
        return packet[0] >> 4


    @staticmethod
    def parse_packet(data: bytes) -> Union[IPv4Packet, IPv6Packet]:
        packet_ver = toolkit.packet_version(data)

        if packet_ver == 4:
            packet = IPv4Packet(data)
        elif packet_ver == 6:
            packet = IPv6Packet(data)
        else:
            raise ValueError(f'Unsupported IP packet version: {packet_ver}')

        return packet
    

    @staticmethod
    def print_packet(packet: Union[IPv4Packet, IPv6Packet], prefix=None):
        if packet[ip.tcp.TCP] and not packet[ip.ip6.IP6]:
            print(
                prefix or "", packet.src_s, "->", packet.dst_s, 
                packet[ip.tcp.TCP].flags_t,
                packet.len,
                packet.highest_layer.body_bytes[:25] or ""
            )


class VirtualAdapter:
    def __init__(self, address, name):
        self.__tun = None
        self.name = name
        self.address = address


    async def create_interface(self):
        try:
            self.__tun = await aiofiles.open("/dev/net/tun", "r+b", buffering=0)
            fd = self.__tun.fileno() 

            ifr = struct.pack("16sH", self.name.encode("ASCII"), IFF_TUN | IFF_NO_PI)
            ioctl(fd, TUNSETIFF, ifr)

            logging.info("Successfully created TUN interface: %s (FD: %d)", self.name, fd)
            
            #set address for interface:
            toolkit.run(f"/sbin/ip addr add {self.address} dev {self.name}")
            toolkit.run(f"/sbin/ip link set dev {self.name} mtu {MTU}")

            #up interface
            toolkit.run(f"/sbin/ip link set dev {self.name} up")
            
            
        except PermissionError:
            logging.error("Permission denied. Ensure the script is running with root access (sudo).")
        except Exception as e:
            logging.error("Failed to create adapter: %s", e)
            if self.__tun:
                # If creation fails, ensure the aiofiles object is closed
                await self.__tun.close()
        

    async def read(self) -> bytes:
        packet = await self.__tun.read(MTU)
        return packet
    

    async def write(self, packet: bytes):
        return await self.__tun.write(packet)
        

async def create_adapter(address, name):
    adapter = VirtualAdapter(address, name)
    await adapter.create_interface()
    return adapter


if __name__ == "__main__":
    x = asyncio.run(create_adapter("10.0.0.2/24", "vpn"))
        
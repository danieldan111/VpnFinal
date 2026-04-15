import os
import queue
import threading
import socket
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#dh parms:
#2048-bit MODP Group (safe prime)
PREDEFINED_PARAMETERS = dh.DHParameterNumbers(
    p=int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
    ),
    g=2
).parameters()

MAX_PACKET_SIZE = 10 * 1024 * 1024  # 10 MB DoS protection limit


class SecureSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.aes = None
        self.queue = queue.Queue()  # For GUI-friendly message handling

    
    def send_raw(self, data: bytes):
        length = len(data).to_bytes(4, "big")
        self.sock.sendall(length + data)

    def recv_raw(self) -> bytes:
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            raise ConnectionError("Connection closed")
        length = int.from_bytes(length_bytes, "big")
        
        if length > MAX_PACKET_SIZE:
            raise ValueError("Payload exceeds maximum allowed size (DoS Protection)")

        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed during recv")
            data += chunk
        return data


    def server_handshake(self):
        parameters = PREDEFINED_PARAMETERS

        server_private = parameters.generate_private_key()
        server_public = server_private.public_key()

        server_pub_bytes = server_public.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        self.send_raw(server_pub_bytes)

        client_pub_bytes = self.recv_raw()
        client_public = load_pem_public_key(client_pub_bytes)

        shared = server_private.exchange(client_public)

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'vpn-control'
        ).derive(shared)

        self.aes = AESGCM(key)

    def client_handshake(self):
        server_pub_bytes = self.recv_raw()
        server_public = load_pem_public_key(server_pub_bytes)

        parameters = PREDEFINED_PARAMETERS
        client_private = parameters.generate_private_key()
        client_public = client_private.public_key()

        client_pub_bytes = client_public.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        self.send_raw(client_pub_bytes)

        shared = client_private.exchange(server_public)
        
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'vpn-control'
        ).derive(shared)

        self.aes = AESGCM(key)

    
    def send_json(self, data: dict):
        payload = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, payload, None)
        self.send_raw(nonce + ciphertext)

    def recv_json(self) -> dict:
        packet = self.recv_raw()
        nonce, ciphertext = packet[:12], packet[12:]
        payload = self.aes.decrypt(nonce, ciphertext, None)
        return json.loads(payload.decode('utf-8'))
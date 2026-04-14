import os
import struct
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BUFFER = 4096
logging.basicConfig(level=logging.INFO)

class KeyGenerator:
    @staticmethod
    def generate_x25519_keypair():
        """Generates an extremely fast, secure Elliptic Curve keypair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize to bytes so they can be sent over the network
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, pub_bytes

    @staticmethod
    def derive_aes_key(private_key, peer_public_bytes):
        """Uses Elliptic Curve Diffie-Hellman (ECDH) to derive a shared AES key."""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        
        # Pass the shared secret through HKDF to get a perfect 32-byte AES key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'vpn-udp-tunnel'
        ).derive(shared_secret)
        
        return derived_key


class VpnCipher:
    """Handles AES-GCM Encryption and Sequence Number tracking to prevent Replay Attacks."""
    def __init__(self, aes_key: bytes):
        self.aesgcm = AESGCM(aes_key)
        self.send_sequence = 0
        self.highest_recv_sequence = -1

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypts data and attaches the sequence number to the front."""
        self.send_sequence += 1
        
        # Pack the sequence number into an 8-byte (64-bit) network-order format
        seq_bytes = struct.pack("!Q", self.send_sequence)
        
        # AES-GCM needs a 12-byte nonce. We pad the 8-byte sequence with 4 zero bytes.
        nonce = b'\x00\x00\x00\x00' + seq_bytes
        
        # Encrypt the payload
        ciphertext = self.aesgcm.encrypt(nonce, msg, associated_data=None)
        
        # Prepend the sequence bytes to the ciphertext so the receiver knows the nonce
        return seq_bytes + ciphertext

    def decrypt(self, encrypted_packet: bytes) -> bytes:
        """Extracts the sequence number, checks for replay attacks, and decrypts."""
        if len(encrypted_packet) < 8 + 16:  # Minimum size: 8 byte seq + 16 byte GCM tag
            raise ValueError("Packet too small")

        # Extract the sequence number from the front of the packet
        seq_bytes = encrypted_packet[:8]
        ciphertext = encrypted_packet[8:]
        
        recv_sequence = struct.unpack("!Q", seq_bytes)[0]

        # ANTI-REPLAY CHECK: Drop packets that are older than our highest seen sequence
        if recv_sequence <= self.highest_recv_sequence:
            raise ValueError(f"Replay attack detected! Sequence {recv_sequence} is too old.")

        # Reconstruct the 12-byte nonce
        nonce = b'\x00\x00\x00\x00' + seq_bytes
        
        # Decrypt (will throw InvalidTag exception if tampered with)
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        
        # Update the highest sequence we've seen
        self.highest_recv_sequence = recv_sequence
        
        return plaintext
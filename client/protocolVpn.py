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
    """Handles AES-GCM Encryption and an Anti-Replay Sliding Window."""
    def __init__(self, aes_key: bytes):
        self.aesgcm = AESGCM(aes_key)
        self.send_sequence = 0
        
        # Sliding Window State
        self.highest_recv_sequence = 0
        self.replay_window = 0  # 64-bit integer acting as a bitmask

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypts data and attaches the sequence number to the front."""
        self.send_sequence += 1
        
        # Pack the sequence number into an 8-byte (64-bit) network-order format
        seq_bytes = struct.pack("!Q", self.send_sequence)
        
        # AES-GCM needs a 12-byte nonce. We pad the 8-byte sequence with 4 zero bytes.
        nonce = b'\x00\x00\x00\x00' + seq_bytes
        
        # Encrypt the payload
        ciphertext = self.aesgcm.encrypt(nonce, msg, associated_data=None)
        return seq_bytes + ciphertext

    def decrypt(self, encrypted_packet: bytes) -> bytes:
        """Extracts sequence number, checks sliding window for replays, and decrypts."""
        if len(encrypted_packet) < 8 + 16:  
            raise ValueError("Packet too small")

        seq_bytes = encrypted_packet[:8]
        ciphertext = encrypted_packet[8:]
        recv_sequence = struct.unpack("!Q", seq_bytes)[0]

        # --- 1. SLIDING WINDOW REPLAY CHECK ---
        if recv_sequence <= self.highest_recv_sequence:
            diff = self.highest_recv_sequence - recv_sequence
            # If it's older than our 64-packet window, drop it
            if diff >= 64:
                raise ValueError(f"Replay attack detected! Sequence {recv_sequence} is too old.")
            
            # Check if we have already seen this exact sequence in our window
            if (self.replay_window & (1 << diff)) != 0:
                raise ValueError(f"Replay attack detected! Sequence {recv_sequence} was already received.")

        # --- 2. DECRYPT (AUTHENTICATE) ---
        # If an attacker tampered with the packet, this will throw an InvalidTag exception
        # before we ever update our sequence window!
        nonce = b'\x00\x00\x00\x00' + seq_bytes
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        
        # --- 3. UPDATE WINDOW (ONLY AFTER AUTHENTICATION SUCCESS) ---
        if recv_sequence > self.highest_recv_sequence:
            diff = recv_sequence - self.highest_recv_sequence
            if diff < 64:
                # Shift the window and add the new packet
                self.replay_window = (self.replay_window << diff) | 1
            else:
                # We jumped too far ahead, reset the window
                self.replay_window = 1
            self.highest_recv_sequence = recv_sequence
        else:
            # It's an out-of-order packet within the window. Mark its specific bit as received.
            diff = self.highest_recv_sequence - recv_sequence
            self.replay_window |= (1 << diff)

        return plaintext
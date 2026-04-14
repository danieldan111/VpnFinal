import os
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


BUFFER = 4096
logging.basicConfig(level=logging.DEBUG)

class KeyGenerator:
    @staticmethod
    def generate_keys():
        private_file = "server_private.pem"
        public_file = "server_public.pem"

        if not os.path.exists(private_file):
            logging.info("Generating new 2048-bit RSA keypair...")

            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            with open(private_file, "wb") as f:
                f.write(private_key)
            with open(public_file, "wb") as f:
                f.write(public_key)

            logging.info("Keys saved.")
        else:
            logging.info("Keys already exist, nothing to do.")
    
    
    @staticmethod
    def load_keys():
        with open("server_private.pem", "rb") as f:
            server_private = RSA.import_key(f.read())

        with open("server_public.pem", "rb") as f:
            server_public = RSA.import_key(f.read())

        return server_private, server_public


    @staticmethod
    def generate_aes():
        aes_key = os.urandom(32)
        logging.debug("generated key %s", aes_key)
        return aes_key
    

class KeySwitch:
    @staticmethod
    def send_public_key(sock, addr, server_public):
        sock.sendto(server_public.export_key(), addr)
        logging.info("sent server public key to %s", addr)


    @staticmethod
    def send_aes_key(sock, key, addr, server_public):
        cipher_rsa = PKCS1_OAEP.new(server_public)
        enc_aes_key = cipher_rsa.encrypt(key)
        sock.sendto(b"SENK" + enc_aes_key, addr)
        logging.info("Sent encrypted AES key to server")



    @staticmethod
    def decrypt_aes_key(aes, server_private):
        cipher_rsa = PKCS1_OAEP.new(server_private)
        aes_key = cipher_rsa.decrypt(aes)
        logging.debug("aes key recived and decrypted %s", aes_key)
        return aes_key
    


class AesEncryptDecrypt:
    @staticmethod
    def aes_encrypt(aes_key, msg: bytes):
        nonce = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        encrypted = cipher.encrypt(msg)
        return nonce + encrypted

    @staticmethod
    def aes_decrypt(aes_key, data: bytes):
        nonce = data[:16]
        enc_msg = data[16:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        msg = cipher.decrypt(enc_msg)
        return msg
import hashlib
import hmac
import struct
from typing import Optional
from crypto.rc4 import RC4

def derive_session_key(password_hash: bytes, server_challenge: bytes, 
                       client_challenge: bytes) -> bytes:
    md5_hash = hashlib.md5()
    md5_hash.update(server_challenge)
    md5_hash.update(client_challenge)
    
    return hmac.new(password_hash, md5_hash.digest(), hashlib.md5).digest()


def decrypt_secret_data(encrypted_data: bytes, session_key: bytes, 
                        encryption_type: int = 1) -> bytes:
    if encryption_type == 1:
        rc4 = RC4(session_key)
        return rc4.decrypt(encrypted_data)
    elif encryption_type == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except ImportError:
            raise NotImplementedError("AES decryption requires cryptography library")
    else:
        raise ValueError(f"Unknown encryption type: {encryption_type}")


def compute_response_key(session_key: bytes, salt: bytes) -> bytes:
    return hmac.new(session_key, salt, hashlib.md5).digest()

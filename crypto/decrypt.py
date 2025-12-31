import hashlib
import struct
from typing import Optional, Tuple, Dict, List
from crypto.rc4 import RC4
from crypto.des import DES, str_to_key

def decrypt_hash(encrypted_hash: bytes, rid: int, session_key: bytes,
                 encryption_type: int = 1) -> bytes:
    if encryption_type == 1:
        rc4_key = hashlib.md5(session_key + struct.pack("<I", rid)).digest()
        rc4 = RC4(rc4_key)
        decrypted = rc4.decrypt(encrypted_hash)
    elif encryption_type == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            aes_key = session_key[:16]
            iv = encrypted_hash[:16]
            ciphertext = encrypted_hash[16:]
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                          backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        except ImportError:
            raise NotImplementedError("AES decryption requires cryptography library")
    else:
        return encrypted_hash
    
    return remove_des_layer(decrypted, rid)


def remove_des_layer(hash_data: bytes, rid: int) -> bytes:
    if len(hash_data) < 16:
        return hash_data
    
    rid_bytes = struct.pack("<I", rid)
    
    key1 = str_to_key(rid_bytes + rid_bytes[:3])
    key2 = str_to_key(rid_bytes[3:4] + rid_bytes + rid_bytes[:2])
    
    des1 = DES(key1)
    des2 = DES(key2)
    
    part1 = des1.decrypt(hash_data[:8])
    part2 = des2.decrypt(hash_data[8:16])
    
    return part1 + part2


def decrypt_aes_hash(encrypted_hash: bytes, session_key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        aes_key = session_key[:16]
        iv = encrypted_hash[:16]
        ciphertext = encrypted_hash[16:]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                      backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except ImportError:
        raise NotImplementedError("AES decryption requires cryptography library")


def decrypt_supplemental_credentials(encrypted_blob: bytes, 
                                     session_key: bytes) -> Dict[str, any]:
    rc4 = RC4(session_key)
    decrypted = rc4.decrypt(encrypted_blob)
    
    result = {}
    
    try:
        offset = 0
        
        if len(decrypted) < 4:
            return result
        
        prefix = decrypted[offset:offset + 4]
        offset += 4
        
        if len(decrypted) < offset + 4:
            return result
        
        num_packages = struct.unpack("<I", decrypted[offset:offset + 4])[0]
        offset += 4
        
        for _ in range(num_packages):
            if offset + 4 > len(decrypted):
                break
            
            name_len = struct.unpack("<H", decrypted[offset:offset + 2])[0]
            offset += 2
            
            data_len = struct.unpack("<H", decrypted[offset:offset + 2])[0]
            offset += 2
            
            if offset + name_len > len(decrypted):
                break
            name = decrypted[offset:offset + name_len].decode("utf-16-le", errors="ignore")
            offset += name_len
            
            if offset + data_len > len(decrypted):
                break
            data = decrypted[offset:offset + data_len]
            offset += data_len
            
            result[name] = data
    except Exception:
        pass
    
    return result


def extract_cleartext_password(supplemental_creds: Dict[str, any]) -> Optional[str]:
    if "Primary:CLEARTEXT" in supplemental_creds:
        try:
            return supplemental_creds["Primary:CLEARTEXT"].decode("utf-16-le").rstrip("\x00")
        except:
            pass
    return None


def extract_kerberos_keys(supplemental_creds: Dict[str, any]) -> List[Dict[str, any]]:
    keys = []
    
    for name in ["Primary:Kerberos-Newer-Keys", "Primary:Kerberos"]:
        if name in supplemental_creds:
            data = supplemental_creds[name]
            try:
                parsed = parse_kerberos_storage(data)
                keys.extend(parsed)
            except:
                pass
    
    return keys


def parse_kerberos_storage(data: bytes) -> List[Dict[str, any]]:
    keys = []
    
    try:
        offset = 0
        
        revision = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        
        flags = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        
        cred_count = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        
        offset += 2
        
        for _ in range(cred_count):
            if offset + 16 > len(data):
                break
            
            offset += 2
            
            key_type = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
            
            offset += 4
            
            key_length = struct.unpack("<I", data[offset:offset + 4])[0]
            offset += 4
            
            key_offset = struct.unpack("<I", data[offset:offset + 4])[0]
            offset += 4
            
            if key_offset + key_length <= len(data):
                key_data = data[key_offset:key_offset + key_length]
                keys.append({
                    "type": key_type,
                    "data": key_data.hex()
                })
    except:
        pass
    
    return keys

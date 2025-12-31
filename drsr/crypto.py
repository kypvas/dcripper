"""Decryption routines for DRSR replicated secrets."""
import hashlib
import struct
from typing import Optional, Tuple

# Try pycryptodome first, fall back to pycrypto
try:
    from Cryptodome.Cipher import ARC4, DES, AES
except ImportError:
    from Crypto.Cipher import ARC4, DES, AES


def decrypt_attribute_value(encrypted_data: bytes, session_key: bytes) -> bytes:
    """
    Decrypt a replicated attribute value.

    The encrypted format is:
    - Salt (16 bytes)
    - RC4 encrypted: CRC32 (4 bytes) + plaintext

    Args:
        encrypted_data: The encrypted attribute value
        session_key: The session key from NTLM authentication

    Returns:
        The decrypted plaintext (without CRC32 header)
    """
    if len(encrypted_data) < 20:
        return b""

    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Derive RC4 key: MD5(session_key + salt)
    md5 = hashlib.md5()
    md5.update(session_key)
    md5.update(salt)
    rc4_key = md5.digest()

    # Decrypt with RC4
    cipher = ARC4.new(rc4_key)
    plaintext = cipher.decrypt(ciphertext)

    # First 4 bytes are CRC32 checksum (we skip it)
    return plaintext[4:]


def decrypt_hash(encrypted_data: bytes, session_key: bytes) -> bytes:
    """
    Decrypt a password hash (unicodePwd or similar).

    Args:
        encrypted_data: The encrypted hash (36 bytes typically)
        session_key: The session key from NTLM authentication

    Returns:
        The decrypted 16-byte NT hash
    """
    decrypted = decrypt_attribute_value(encrypted_data, session_key)

    # The decrypted data should be 16 bytes (NT hash)
    if len(decrypted) == 16:
        return decrypted
    elif len(decrypted) > 16:
        return decrypted[:16]
    else:
        return decrypted


def rid_from_sid(sid: bytes) -> int:
    """Extract the RID (last sub-authority) from a SID."""
    if len(sid) < 8:
        return 0

    # SID structure: revision (1) + num_auths (1) + authority (6) + sub_auths (4 each)
    num_auths = sid[1]
    if len(sid) < 8 + (num_auths * 4):
        return 0

    # RID is the last sub-authority
    rid_offset = 8 + ((num_auths - 1) * 4)
    rid = struct.unpack("<I", sid[rid_offset:rid_offset + 4])[0]
    return rid


def remove_des_layer(encrypted_hash: bytes, rid: int) -> bytes:
    """
    Remove the DES layer from NT/LM hash.

    Windows stores hashes with an additional DES encryption layer using the RID.
    This is on top of the RC4 layer that decrypt_attribute_value removes.

    Per MS-SAMR 2.2.11.1.3:
    - Key1 = RID bytes [0, 1, 2, 3, 0, 1, 2]
    - Key2 = RID bytes [3, 0, 1, 2, 3, 0, 1]

    Args:
        encrypted_hash: The hash after RC4 decryption (16 bytes)
        rid: The user's RID

    Returns:
        The final decrypted 16-byte hash
    """
    if len(encrypted_hash) != 16:
        return encrypted_hash

    # Derive two 7-byte DES keys from the RID
    key1, key2 = _derive_des_keys(rid)

    # Decrypt each 8-byte half
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)

    return des1.decrypt(encrypted_hash[:8]) + des2.decrypt(encrypted_hash[8:16])


def _derive_des_keys(rid: int) -> Tuple[bytes, bytes]:
    """
    Derive Key1 and Key2 from RID per MS-SAMR 2.2.11.1.3.

    Let I be the little-endian RID as bytes [0, 1, 2, 3].
    Key1 = transformKey([I[0], I[1], I[2], I[3], I[0], I[1], I[2]])
    Key2 = transformKey([I[3], I[0], I[1], I[2], I[3], I[0], I[1]])
    """
    # Pack RID as little-endian 4 bytes
    rid_bytes = struct.pack("<I", rid)

    # Build 7-byte key inputs
    key1_bytes = bytes([
        rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3],
        rid_bytes[0], rid_bytes[1], rid_bytes[2]
    ])
    key2_bytes = bytes([
        rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2],
        rid_bytes[3], rid_bytes[0], rid_bytes[1]
    ])

    return _transform_key(key1_bytes), _transform_key(key2_bytes)


def _transform_key(input_key: bytes) -> bytes:
    """
    Transform 7 bytes into 8-byte DES key per MS-SAMR Section 5.1.3.

    This expands the 7-byte key to 8 bytes by spreading bits.
    """
    if len(input_key) != 7:
        raise ValueError("Input key must be 7 bytes")

    output = bytearray(8)
    output[0] = input_key[0] >> 1
    output[1] = ((input_key[0] & 0x01) << 6) | (input_key[1] >> 2)
    output[2] = ((input_key[1] & 0x03) << 5) | (input_key[2] >> 3)
    output[3] = ((input_key[2] & 0x07) << 4) | (input_key[3] >> 4)
    output[4] = ((input_key[3] & 0x0F) << 3) | (input_key[4] >> 5)
    output[5] = ((input_key[4] & 0x1F) << 2) | (input_key[5] >> 6)
    output[6] = ((input_key[5] & 0x3F) << 1) | (input_key[6] >> 7)
    output[7] = input_key[6] & 0x7F

    # Shift left by 1 and mask off parity bit position
    for i in range(8):
        output[i] = (output[i] << 1) & 0xFE

    return bytes(output)


def decrypt_nt_hash(encrypted_data: bytes, session_key: bytes, rid: int) -> bytes:
    """
    Fully decrypt an NT hash from replicated data.

    This removes both the RC4 layer and the DES layer.

    Args:
        encrypted_data: The encrypted unicodePwd value
        session_key: The session key from NTLM authentication
        rid: The user's RID (from SID)

    Returns:
        The final 16-byte NT hash
    """
    # First remove RC4 layer
    after_rc4 = decrypt_hash(encrypted_data, session_key)

    # Then remove DES layer
    final_hash = remove_des_layer(after_rc4, rid)

    return final_hash

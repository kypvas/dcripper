import hashlib
import hmac
import struct
import os
from typing import Tuple, Optional
from crypto.rc4 import RC4
from crypto.des import DES
from crypto.md4 import md4

def compute_lm_hash(password: str) -> bytes:
    password = password.upper()[:14].ljust(14, '\x00')
    key1 = _str_to_key(password[:7].encode('latin-1'))
    key2 = _str_to_key(password[7:14].encode('latin-1'))
    magic = b"KGS!@#$%"
    des1 = DES(key1)
    des2 = DES(key2)
    return des1.encrypt(magic) + des2.encrypt(magic)

def compute_ntlm_hash(password: str) -> bytes:
    return md4(password.encode("utf-16-le"))

def _str_to_key(s: bytes) -> bytes:
    key = bytearray(8)
    key[0] = s[0] >> 1
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
    key[4] = ((s[3] & 0x0f) << 3) | (s[4] >> 5)
    key[5] = ((s[4] & 0x1f) << 2) | (s[5] >> 6)
    key[6] = ((s[5] & 0x3f) << 1) | (s[6] >> 7)
    key[7] = s[6] & 0x7f
    for i in range(8):
        key[i] = (key[i] << 1) & 0xfe
        key[i] = _set_odd_parity(key[i])
    return bytes(key)

def _set_odd_parity(byte: int) -> int:
    parity = 0
    for i in range(7):
        parity += (byte >> i) & 1
    if parity % 2 == 0:
        byte |= 1
    return byte

class NTLMAuth:
    NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
    NTLMSSP_NEGOTIATE = 1
    NTLMSSP_CHALLENGE = 2
    NTLMSSP_AUTH = 3
    
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    NTLMSSP_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_56 = 0x80000000
    
    def __init__(self, domain: str, username: str, password: str = "", ntlm_hash: str = ""):
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.ntlm_hash = bytes.fromhex(ntlm_hash) if ntlm_hash else b""
        self.session_key: Optional[bytes] = None
        self._server_challenge: Optional[bytes] = None
        self._exported_session_key: Optional[bytes] = None
        self._negotiate_message: Optional[bytes] = None
        self._challenge_message: Optional[bytes] = None

    def get_negotiate_message(self) -> bytes:
        flags = (
            self.NTLMSSP_NEGOTIATE_UNICODE |
            self.NTLMSSP_REQUEST_TARGET |
            self.NTLMSSP_NEGOTIATE_SIGN |
            self.NTLMSSP_NEGOTIATE_SEAL |
            self.NTLMSSP_NEGOTIATE_NTLM |
            self.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
            self.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
            self.NTLMSSP_NEGOTIATE_128 |
            self.NTLMSSP_NEGOTIATE_KEY_EXCH |
            self.NTLMSSP_NEGOTIATE_56
        )

        message = bytearray()
        message.extend(self.NTLMSSP_SIGNATURE)
        message.extend(struct.pack("<I", self.NTLMSSP_NEGOTIATE))
        message.extend(struct.pack("<I", flags))
        message.extend(struct.pack("<HHI", 0, 0, 0))
        message.extend(struct.pack("<HHI", 0, 0, 0))
        message.extend(struct.pack("<BB", 10, 0))
        message.extend(struct.pack("<H", 0))

        self._negotiate_message = bytes(message)
        return self._negotiate_message
    
    def process_challenge(self, challenge_message: bytes) -> bytes:
        if challenge_message[:8] != self.NTLMSSP_SIGNATURE:
            raise ValueError("Invalid NTLM signature")

        msg_type = struct.unpack("<I", challenge_message[8:12])[0]
        if msg_type != self.NTLMSSP_CHALLENGE:
            raise ValueError(f"Expected CHALLENGE message, got {msg_type}")

        self._server_challenge = challenge_message[24:32]
        flags = struct.unpack("<I", challenge_message[20:24])[0]

        # Extract Target Info from challenge message
        target_info_len = struct.unpack("<H", challenge_message[40:42])[0]
        target_info_offset = struct.unpack("<I", challenge_message[44:48])[0]
        self._target_info = challenge_message[target_info_offset:target_info_offset + target_info_len]

        # Store messages for MIC calculation
        self._challenge_message = challenge_message


        client_challenge = os.urandom(8)

        if self.ntlm_hash:
            nt_hash = self.ntlm_hash
        else:
            nt_hash = compute_ntlm_hash(self.password)

        nt_response, lm_response, session_base_key = self._compute_ntlmv2_response(
            nt_hash, self._server_challenge, client_challenge, self._target_info
        )

        self._exported_session_key = os.urandom(16)
        encrypted_random_session_key = RC4(session_base_key).encrypt(self._exported_session_key)
        self.session_key = self._exported_session_key

        return self._build_auth_message_with_mic(
            lm_response, nt_response, encrypted_random_session_key, flags,
            session_base_key
        )
    
    def _compute_ntlmv2_response(
        self, nt_hash: bytes, server_challenge: bytes, client_challenge: bytes,
        target_info: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        user_domain = (self.username.upper() + self.domain).encode("utf-16-le")
        ntlmv2_hash = hmac.new(nt_hash, user_domain, hashlib.md5).digest()

        timestamp = self._get_windows_timestamp()

        # Build NTLMv2 client blob
        blob = bytearray()
        blob.append(0x01)  # RespType
        blob.append(0x01)  # HiRespType
        blob.extend(b"\x00\x00")  # Reserved1
        blob.extend(b"\x00\x00\x00\x00")  # Reserved2
        blob.extend(struct.pack("<Q", timestamp))  # TimeStamp
        blob.extend(client_challenge)  # ChallengeFromClient
        blob.extend(b"\x00\x00\x00\x00")  # Reserved3
        blob.extend(target_info)  # Use server's target info

        temp = server_challenge + bytes(blob)
        nt_proof_str = hmac.new(ntlmv2_hash, temp, hashlib.md5).digest()
        nt_response = nt_proof_str + bytes(blob)

        lm_temp = server_challenge + client_challenge
        lm_response = hmac.new(ntlmv2_hash, lm_temp, hashlib.md5).digest() + client_challenge

        session_base_key = hmac.new(ntlmv2_hash, nt_proof_str, hashlib.md5).digest()

        return nt_response, lm_response, session_base_key
    
    def _get_windows_timestamp(self) -> int:
        import time
        unix_time = time.time()
        windows_time = int((unix_time + 11644473600) * 10000000)
        return windows_time
    
    def _filter_target_info(self, target_info: bytes) -> bytes:
        """Filter out MsvAvTimestamp (type 7) to avoid MIC requirement."""
        result = bytearray()
        offset = 0

        while offset < len(target_info):
            av_id = struct.unpack("<H", target_info[offset:offset+2])[0]
            av_len = struct.unpack("<H", target_info[offset+2:offset+4])[0]

            if av_id == 0:  # MsvAvEOL
                result.extend(struct.pack("<HH", 0, 0))
                break
            elif av_id != 7:  # Skip MsvAvTimestamp (type 7)
                result.extend(target_info[offset:offset+4+av_len])

            offset += 4 + av_len

        return bytes(result)

    def _build_av_pairs(self) -> bytes:
        pairs = bytearray()

        domain_bytes = self.domain.encode("utf-16-le")
        pairs.extend(struct.pack("<HH", 2, len(domain_bytes)))
        pairs.extend(domain_bytes)

        pairs.extend(struct.pack("<HH", 0, 0))

        return bytes(pairs)
    
    def _build_auth_message_with_mic(
        self, lm_response: bytes, nt_response: bytes,
        encrypted_session_key: bytes, flags: int,
        session_base_key: bytes
    ) -> bytes:
        domain_bytes = self.domain.encode("utf-16-le")
        user_bytes = self.username.encode("utf-16-le")
        workstation = b""  # Empty workstation

        # Base structure: 8 + 4 + 8*6 + 4 = 64 bytes
        # + Version (8 bytes) + MIC (16 bytes) = 88 bytes
        offset = 88

        message = bytearray()
        message.extend(self.NTLMSSP_SIGNATURE)
        message.extend(struct.pack("<I", self.NTLMSSP_AUTH))

        message.extend(struct.pack("<HHI", len(lm_response), len(lm_response), offset))
        offset += len(lm_response)

        message.extend(struct.pack("<HHI", len(nt_response), len(nt_response), offset))
        offset += len(nt_response)

        message.extend(struct.pack("<HHI", len(domain_bytes), len(domain_bytes), offset))
        offset += len(domain_bytes)

        message.extend(struct.pack("<HHI", len(user_bytes), len(user_bytes), offset))
        offset += len(user_bytes)

        message.extend(struct.pack("<HHI", len(workstation), len(workstation), offset))
        offset += len(workstation)

        message.extend(struct.pack("<HHI", len(encrypted_session_key), len(encrypted_session_key), offset))

        message.extend(struct.pack("<I", flags))

        # Version structure (8 bytes):
        # Major(1) + Minor(1) + Build(2) + Reserved(3) + Revision(1)
        # Windows 10 style version
        message.extend(b"\x0a\x00\x00\x00\x00\x00\x00\x0f")

        # MIC placeholder (16 bytes of zeros for now)
        mic_offset = len(message)
        message.extend(b"\x00" * 16)

        # Payload
        message.extend(lm_response)
        message.extend(nt_response)
        message.extend(domain_bytes)
        message.extend(user_bytes)
        message.extend(workstation)
        message.extend(encrypted_session_key)

        # Calculate MIC: HMAC_MD5(Session Base Key, NEGOTIATE || CHALLENGE || AUTHENTICATE)
        # where AUTHENTICATE has MIC set to zeros
        mic_data = self._negotiate_message + self._challenge_message + bytes(message)
        mic = hmac.new(session_base_key, mic_data, hashlib.md5).digest()

        # Replace MIC placeholder with actual MIC
        message[mic_offset:mic_offset+16] = mic

        return bytes(message)
    
    def get_session_key(self) -> bytes:
        if not self.session_key:
            raise ValueError("Session key not established - complete authentication first")
        return self.session_key

    def get_signing_key(self, mode: str = 'Client') -> bytes:
        """Derive signing key from session key (MS-NLMP 3.4.4)."""
        if not self.session_key:
            raise ValueError("Session key not established")
        if mode == 'Client':
            magic = b"session key to client-to-server signing key magic constant\x00"
        else:
            magic = b"session key to server-to-client signing key magic constant\x00"
        return hashlib.md5(self.session_key + magic).digest()

    def get_sealing_key(self, mode: str = 'Client') -> bytes:
        """Derive sealing key from session key (MS-NLMP 3.4.4)."""
        if not self.session_key:
            raise ValueError("Session key not established")
        if mode == 'Client':
            magic = b"session key to client-to-server sealing key magic constant\x00"
        else:
            magic = b"session key to server-to-client sealing key magic constant\x00"
        return hashlib.md5(self.session_key + magic).digest()

    def get_ntlm_flags(self) -> int:
        """Return the negotiated flags used during authentication."""
        return (
            self.NTLMSSP_NEGOTIATE_UNICODE |
            self.NTLMSSP_REQUEST_TARGET |
            self.NTLMSSP_NEGOTIATE_SIGN |
            self.NTLMSSP_NEGOTIATE_SEAL |
            self.NTLMSSP_NEGOTIATE_NTLM |
            self.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
            self.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
            self.NTLMSSP_NEGOTIATE_128 |
            self.NTLMSSP_NEGOTIATE_KEY_EXCH |
            self.NTLMSSP_NEGOTIATE_56
        )


class NTLMSecurity:
    """Handles NTLM message signing and sealing for RPC."""

    def __init__(self, session_key: bytes, flags: int):
        self.session_key = session_key
        self.flags = flags
        self.sequence = 0

        # Derive keys
        self.client_signing_key = hashlib.md5(
            session_key + b"session key to client-to-server signing key magic constant\x00"
        ).digest()
        self.client_sealing_key = hashlib.md5(
            session_key + b"session key to client-to-server sealing key magic constant\x00"
        ).digest()
        self.server_signing_key = hashlib.md5(
            session_key + b"session key to server-to-client signing key magic constant\x00"
        ).digest()
        self.server_sealing_key = hashlib.md5(
            session_key + b"session key to server-to-client sealing key magic constant\x00"
        ).digest()

        # Create RC4 cipher handles - these maintain state across messages
        self.client_seal_handle = RC4(self.client_sealing_key)
        self.server_seal_handle = RC4(self.server_sealing_key)

    def unseal_response(self, sealed_data: bytes) -> bytes:
        """Decrypt response data from server using server sealing key."""
        return self.server_seal_handle.encrypt(sealed_data)

    def sign(self, message: bytes) -> bytes:
        """Sign a message and return the signature (MS-NLMP 3.4.4)."""
        # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY + NTLMSSP_NEGOTIATE_KEY_EXCH
        seq_bytes = struct.pack("<I", self.sequence)

        # Calculate HMAC-MD5 over sequence + message
        checksum = hmac.new(self.client_signing_key, seq_bytes + message, hashlib.md5).digest()[:8]

        # Encrypt the checksum with RC4
        encrypted_checksum = self.client_seal_handle.encrypt(checksum)

        # Build signature: Version(4) + Checksum(8) + SeqNum(4)
        signature = struct.pack("<I", 1)  # Version = 1
        signature += encrypted_checksum
        signature += seq_bytes

        return signature

    def seal(self, message: bytes) -> Tuple[bytes, bytes]:
        """Seal (encrypt) a message and return (sealed_message, signature)."""
        # For NTLM2 with extended session security:
        # The signature is computed over the plaintext but using the packet structure
        seq_bytes = struct.pack("<I", self.sequence)

        # Encrypt the message first
        sealed_message = self.client_seal_handle.encrypt(message)

        # Calculate signature: HMAC-MD5(signingKey, seqNum + plaintext)[:8]
        # Note: We sign the original message, not the encrypted one
        checksum = hmac.new(self.client_signing_key, seq_bytes + message, hashlib.md5).digest()[:8]

        # The checksum is encrypted with RC4 separately
        # Need a new handle for the checksum encryption (already used for message)
        checksum_handle = RC4(self.client_sealing_key)
        # Skip ahead to match the state
        checksum_handle.encrypt(b'\x00' * len(sealed_message))
        encrypted_checksum = checksum_handle.encrypt(checksum)

        # Build signature
        signature = struct.pack("<I", 1)  # Version = 1
        signature += encrypted_checksum
        signature += seq_bytes

        return sealed_message, signature

    def seal_with_reset(self, message_to_encrypt: bytes, message_to_sign: bytes = None) -> Tuple[bytes, bytes]:
        """Seal message using the persistent RC4 handle (as per MS-NLMP).

        Args:
            message_to_encrypt: The stub data to encrypt
            message_to_sign: The full PDU to sign (if None, uses message_to_encrypt)

        With NTLM2 + KEY_EXCH, the same RC4 stream is used to:
        1. Encrypt the message
        2. Encrypt the HMAC-MD5 checksum
        """
        # SeqNum is packed as signed int per MS-NLMP
        seq_bytes = struct.pack("<i", self.sequence)

        if message_to_sign is None:
            message_to_sign = message_to_encrypt

        # Encrypt the message with the persistent handle
        sealed_message = self.client_seal_handle.encrypt(message_to_encrypt)

        # Calculate checksum: HMAC-MD5(signingKey, seqNum + messageToSign)[:8]
        checksum = hmac.new(self.client_signing_key, seq_bytes + message_to_sign, hashlib.md5).digest()[:8]

        # Encrypt checksum with the SAME RC4 stream (continuing state)
        encrypted_checksum = self.client_seal_handle.encrypt(checksum)

        # Build signature: Version(4) + Checksum(8) + SeqNum(4)
        signature = struct.pack("<I", 1)  # Version = 1
        signature += encrypted_checksum
        signature += struct.pack("<I", self.sequence)  # SeqNum stored as unsigned

        return sealed_message, signature

    def increment_sequence(self):
        """Increment the sequence number after a message."""
        self.sequence += 1

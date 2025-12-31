import struct
import os
from enum import IntEnum
from typing import Optional, Tuple
from transport.ntlm import NTLMSecurity

class PacketType(IntEnum):
    REQUEST = 0
    PING = 1
    RESPONSE = 2
    FAULT = 3
    WORKING = 4
    NOCALL = 5
    REJECT = 6
    ACK = 7
    CL_CANCEL = 8
    FACK = 9
    CANCEL_ACK = 10
    BIND = 11
    BIND_ACK = 12
    BIND_NAK = 13
    ALTER_CONTEXT = 14
    ALTER_CONTEXT_RESP = 15
    AUTH3 = 16
    SHUTDOWN = 17
    CO_CANCEL = 18
    ORPHANED = 19

class AuthType(IntEnum):
    NONE = 0
    NTLMSSP = 10
    GSS_NEGOTIATE = 9
    GSS_SCHANNEL = 14
    GSS_KERBEROS = 16

class AuthLevel(IntEnum):
    NONE = 1
    CONNECT = 2
    CALL = 3
    PKT = 4
    PKT_INTEGRITY = 5
    PKT_PRIVACY = 6

class DCERPCClient:
    NDR_UUID = bytes.fromhex("8a885d041ceb11c99fe808002b104860")
    NDR64_UUID = bytes.fromhex("33057171febe4411a05200c04fc2dcd2")
    
    PFC_FIRST_FRAG = 0x01
    PFC_LAST_FRAG = 0x02
    PFC_PENDING_CANCEL = 0x04
    PFC_SUPPORT_HEADER_SIGN = 0x04
    PFC_CONC_MPX = 0x10
    PFC_DID_NOT_EXECUTE = 0x20
    PFC_MAYBE = 0x40
    PFC_OBJECT_UUID = 0x80
    
    def __init__(self, transport, ntlm_auth=None):
        self.transport = transport
        self.ntlm_auth = ntlm_auth
        self.call_id = 0
        self.ctx_id = 0
        self.auth_ctx_id = 79231  # ctx_id + 79231 as per Impacket
        self.max_xmit_frag = 4280
        self.max_recv_frag = 4280
        self._bound = False
        self.session_key: Optional[bytes] = None
        self.auth_level: int = AuthLevel.NONE
        self.ntlm_security: Optional[NTLMSecurity] = None
        
    def bind(self, interface_uuid: bytes, version: Tuple[int, int]) -> bool:
        self.call_id += 1
        
        pdu = bytearray()
        
        pdu.append(5)
        pdu.append(0)
        pdu.append(PacketType.BIND)
        pdu.append(self.PFC_FIRST_FRAG | self.PFC_LAST_FRAG)
        pdu.extend(b"\x10\x00\x00\x00")
        pdu.extend(b"\x00\x00")
        pdu.extend(b"\x00\x00")
        pdu.extend(struct.pack("<I", self.call_id))
        
        pdu.extend(struct.pack("<H", self.max_xmit_frag))
        pdu.extend(struct.pack("<H", self.max_recv_frag))
        pdu.extend(struct.pack("<I", 0))
        
        pdu.append(1)
        pdu.extend(b"\x00" * 3)
        
        pdu.extend(struct.pack("<H", self.ctx_id))
        pdu.append(1)
        pdu.append(0)
        
        pdu.extend(self._pack_uuid(interface_uuid))
        pdu.extend(struct.pack("<HH", version[0], version[1]))
        
        pdu.extend(self._pack_uuid(self.NDR_UUID))
        pdu.extend(struct.pack("<I", 2))
        
        struct.pack_into("<H", pdu, 8, len(pdu))
        
        self.transport.send(bytes(pdu))
        response = self.transport.recv_fragment()
        
        if response[2] == PacketType.BIND_NAK:
            reason = struct.unpack("<H", response[16:18])[0]
            raise Exception(f"Bind rejected with reason: {reason}")
        
        if response[2] != PacketType.BIND_ACK:
            raise Exception(f"Expected BIND_ACK, got {response[2]}")
        
        result = struct.unpack("<H", response[36:38])[0] if len(response) > 37 else 0
        if result != 0:
            pass
        
        self._bound = True
        return True
    
    def bind_with_auth(self, interface_uuid: bytes, version: Tuple[int, int],
                       auth_level: int = AuthLevel.PKT_PRIVACY) -> bool:
        if not self.ntlm_auth:
            raise Exception("NTLM auth required for authenticated bind")
        
        self.call_id += 1
        
        ntlm_negotiate = self.ntlm_auth.get_negotiate_message()
        
        pdu = bytearray()
        
        pdu.append(5)
        pdu.append(0)
        pdu.append(PacketType.BIND)
        pdu.append(self.PFC_FIRST_FRAG | self.PFC_LAST_FRAG)
        pdu.extend(b"\x10\x00\x00\x00")
        pdu.extend(b"\x00\x00")
        pdu.extend(b"\x00\x00")
        pdu.extend(struct.pack("<I", self.call_id))
        
        pdu.extend(struct.pack("<H", self.max_xmit_frag))
        pdu.extend(struct.pack("<H", self.max_recv_frag))
        pdu.extend(struct.pack("<I", 0))
        
        pdu.append(1)
        pdu.extend(b"\x00" * 3)
        
        pdu.extend(struct.pack("<H", self.ctx_id))
        pdu.append(1)
        pdu.append(0)
        
        pdu.extend(self._pack_uuid(interface_uuid))
        pdu.extend(struct.pack("<HH", version[0], version[1]))
        
        pdu.extend(self._pack_uuid(self.NDR_UUID))
        pdu.extend(struct.pack("<I", 2))
        
        sec_trailer_offset = len(pdu)
        pad_len = (4 - (len(pdu) % 4)) % 4
        pdu.extend(b"\x00" * pad_len)
        
        pdu.append(AuthType.NTLMSSP)
        pdu.append(auth_level)
        pdu.append(pad_len)
        pdu.append(0)
        pdu.extend(struct.pack("<I", self.auth_ctx_id))
        
        pdu.extend(ntlm_negotiate)
        
        struct.pack_into("<H", pdu, 8, len(pdu))
        struct.pack_into("<H", pdu, 10, len(ntlm_negotiate))

        self.transport.send(bytes(pdu))
        response = self.transport.recv_fragment()

        if response[2] == PacketType.BIND_NAK:
            reason = struct.unpack("<H", response[16:18])[0]
            raise Exception(f"Authenticated bind rejected: {reason}")

        if response[2] != PacketType.BIND_ACK:
            raise Exception(f"Expected BIND_ACK, got {response[2]}")
        
        auth_len = struct.unpack("<H", response[10:12])[0]
        if auth_len == 0:
            raise Exception("No auth data in BIND_ACK - server rejected auth")
        
        ntlm_challenge = response[-auth_len:]
        
        ntlm_authenticate = self.ntlm_auth.process_challenge(ntlm_challenge)
        
        self._send_auth3(ntlm_authenticate, auth_level)

        self.session_key = self.ntlm_auth.get_session_key()
        self.auth_level = auth_level

        # Set up NTLM security context for signing/sealing
        if auth_level in (AuthLevel.PKT_INTEGRITY, AuthLevel.PKT_PRIVACY):
            ntlm_flags = self.ntlm_auth.get_ntlm_flags()
            self.ntlm_security = NTLMSecurity(self.session_key, ntlm_flags)

        self._bound = True
        return True
    
    def _send_auth3(self, ntlm_authenticate: bytes, auth_level: int):
        self.call_id += 1

        pdu = bytearray()

        # Common header (16 bytes)
        pdu.append(5)  # version major
        pdu.append(0)  # version minor
        pdu.append(PacketType.AUTH3)  # type
        pdu.append(self.PFC_FIRST_FRAG | self.PFC_LAST_FRAG)  # flags
        pdu.extend(b"\x10\x00\x00\x00")  # data representation
        pdu.extend(b"\x00\x00")  # frag_len placeholder
        pdu.extend(b"\x00\x00")  # auth_len placeholder
        pdu.extend(struct.pack("<I", self.call_id))

        # pduData: 4 bytes of padding (as per MS-RPCE 2.2.2.11)
        pdu.extend(b"    ")  # 4 spaces as padding

        # sec_trailer (8 bytes)
        pdu.append(AuthType.NTLMSSP)  # auth_type
        pdu.append(auth_level)  # auth_level
        pdu.append(0)  # auth_pad_len (no padding needed, already 4-byte aligned)
        pdu.append(0)  # auth_reserved
        pdu.extend(struct.pack("<I", self.auth_ctx_id))  # auth_context_id

        # auth_value (NTLM authenticate message)
        pdu.extend(ntlm_authenticate)

        # Update frag_len and auth_len
        struct.pack_into("<H", pdu, 8, len(pdu))
        struct.pack_into("<H", pdu, 10, len(ntlm_authenticate))

        self.transport.send(bytes(pdu))
    
    def call(self, opnum: int, data: bytes, object_uuid: Optional[bytes] = None) -> bytes:
        if not self._bound:
            raise Exception("Must bind before calling")

        self.call_id += 1

        flags = self.PFC_FIRST_FRAG | self.PFC_LAST_FRAG
        if object_uuid:
            flags |= self.PFC_OBJECT_UUID

        # Build base PDU header (will update lengths later)
        pdu = bytearray()
        pdu.append(5)  # version major
        pdu.append(0)  # version minor
        pdu.append(PacketType.REQUEST)
        pdu.append(flags)
        pdu.extend(b"\x10\x00\x00\x00")  # data representation (little endian)
        pdu.extend(b"\x00\x00")  # frag_len placeholder
        pdu.extend(b"\x00\x00")  # auth_len placeholder
        pdu.extend(struct.pack("<I", self.call_id))

        # Request header
        pdu.extend(struct.pack("<I", len(data)))  # alloc_hint
        pdu.extend(struct.pack("<H", self.ctx_id))
        pdu.extend(struct.pack("<H", opnum))

        if object_uuid:
            pdu.extend(self._pack_uuid(object_uuid))

        # Handle authentication
        if self.auth_level in (AuthLevel.PKT_INTEGRITY, AuthLevel.PKT_PRIVACY):
            # Need to add padding, sec_trailer, and auth data
            stub_data = data

            # Calculate padding to align to 4 bytes
            header_len = len(pdu)
            pad_len = (4 - ((header_len + len(stub_data)) % 4)) % 4
            padded_stub = stub_data + (b'\xBB' * pad_len)

            if self.auth_level == AuthLevel.PKT_PRIVACY:
                # Build sec_trailer (8 bytes)
                sec_trailer = bytearray()
                sec_trailer.append(AuthType.NTLMSSP)  # auth_type
                sec_trailer.append(self.auth_level)  # auth_level
                sec_trailer.append(pad_len)  # auth_pad_len
                sec_trailer.append(0)  # auth_reserved
                sec_trailer.extend(struct.pack("<I", self.auth_ctx_id))  # auth_context_id

                # Calculate final lengths BEFORE signing (must match final packet)
                # frag_len = header + padded_stub + sec_trailer (8) + auth_data (16)
                final_frag_len = len(pdu) + len(padded_stub) + 8 + 16
                auth_len = 16  # signature is always 16 bytes

                # Update header with correct lengths BEFORE building message_to_sign
                struct.pack_into("<H", pdu, 8, final_frag_len)
                struct.pack_into("<H", pdu, 10, auth_len)

                # Per MS-RPCE and Impacket: message_to_sign = header + padded_stub + sec_trailer
                # (the whole PDU minus the 16-byte auth_data/signature at the end)
                message_to_sign = bytes(pdu) + padded_stub + bytes(sec_trailer)

                # DEBUG
                import os
                if os.environ.get('DEBUG_RPC'):
                    print(f"[DEBUG] Header len: {len(pdu)}")
                    print(f"[DEBUG] Stub len: {len(stub_data)}, Padded stub len: {len(padded_stub)}, pad_len: {pad_len}")
                    print(f"[DEBUG] sec_trailer: {bytes(sec_trailer).hex()}")
                    print(f"[DEBUG] frag_len: {final_frag_len}, auth_len: {auth_len}")
                    print(f"[DEBUG] header: {bytes(pdu).hex()}")
                    print(f"[DEBUG] padded_stub: {padded_stub.hex()}")
                    print(f"[DEBUG] message_to_sign: {message_to_sign.hex()}")
                    print(f"[DEBUG] message_to_sign len: {len(message_to_sign)}")
                    print(f"[DEBUG] session_key: {self.session_key.hex()}")
                    print(f"[DEBUG] signing_key: {self.ntlm_security.client_signing_key.hex()}")
                    print(f"[DEBUG] sealing_key: {self.ntlm_security.client_sealing_key.hex()}")
                    print(f"[DEBUG] sequence: {self.ntlm_security.sequence}")

                # Seal: encrypt the stub data, sign the PDU
                sealed_stub, signature = self.ntlm_security.seal_with_reset(padded_stub, message_to_sign)

                if os.environ.get('DEBUG_RPC'):
                    print(f"[DEBUG] sealed_stub: {sealed_stub[:32].hex()}...")
                    print(f"[DEBUG] signature: {signature.hex()}")

                # Now build final PDU with sealed data (header already has correct lengths)
                pdu.extend(sealed_stub)
                pdu.extend(sec_trailer)
                pdu.extend(signature)

                self.ntlm_security.increment_sequence()

            elif self.auth_level == AuthLevel.PKT_INTEGRITY:
                # For integrity, stub is not encrypted but signed
                pdu.extend(padded_stub)

                # Add sec_trailer
                sec_trailer = bytearray()
                sec_trailer.append(AuthType.NTLMSSP)
                sec_trailer.append(self.auth_level)
                sec_trailer.append(pad_len)
                sec_trailer.append(0)
                sec_trailer.extend(struct.pack("<I", self.auth_ctx_id))

                # Sign the message: header + stub + sec_trailer (no auth_data)
                message_to_sign = bytes(pdu) + bytes(sec_trailer)
                signature = self.ntlm_security.sign(message_to_sign)

                pdu.extend(sec_trailer)
                pdu.extend(signature)

                struct.pack_into("<H", pdu, 8, len(pdu))
                struct.pack_into("<H", pdu, 10, 16)

                self.ntlm_security.increment_sequence()
        else:
            # No authentication - simple request
            pdu.extend(data)
            struct.pack_into("<H", pdu, 8, len(pdu))

        self.transport.send(bytes(pdu))

        result = b""
        while True:
            response = self.transport.recv_fragment()

            if response[2] == PacketType.FAULT:
                status = struct.unpack("<I", response[24:28])[0]
                raise Exception(f"RPC fault: 0x{status:08x}")

            if response[2] != PacketType.RESPONSE:
                raise Exception(f"Expected RESPONSE, got {response[2]}")

            # Parse response - need to handle auth data if present
            auth_len = struct.unpack("<H", response[10:12])[0]

            if auth_len > 0:
                # Response has authentication data
                # stub_data is between header (24 bytes) and sec_trailer+auth_data
                # sec_trailer is 8 bytes, auth_data is auth_len bytes
                stub_end = len(response) - 8 - auth_len
                stub_data = response[24:stub_end]

                # Extract sec_trailer to get pad length
                sec_trailer_start = stub_end
                auth_pad_len = response[sec_trailer_start + 2]

                if os.environ.get('DEBUG_RPC'):
                    print(f"[DEBUG] Response total len: {len(response)}")
                    print(f"[DEBUG] auth_len: {auth_len}, stub_end: {stub_end}")
                    print(f"[DEBUG] Encrypted stub ({len(stub_data)} bytes): {stub_data[:40].hex()}...")
                    print(f"[DEBUG] auth_pad_len: {auth_pad_len}")

                if self.auth_level == AuthLevel.PKT_PRIVACY and self.ntlm_security:
                    # Decrypt the stub data using server's sealing key
                    stub_data = self.ntlm_security.unseal_response(stub_data)

                    # Also consume 8 bytes of RC4 stream for the signature checksum
                    # (MS-NLMP SEAL: the same RC4 stream encrypts both message and checksum)
                    self.ntlm_security.unseal_response(b'\x00' * 8)

                    if os.environ.get('DEBUG_RPC'):
                        print(f"[DEBUG] Decrypted stub: {stub_data[:40].hex()}...")

                # Remove padding
                if auth_pad_len > 0:
                    stub_data = stub_data[:-auth_pad_len]
            else:
                stub_data = response[24:]

            result += stub_data

            if response[3] & self.PFC_LAST_FRAG:
                break

        return result
    
    def _pack_uuid(self, uuid_bytes: bytes) -> bytes:
        if len(uuid_bytes) != 16:
            raise ValueError("UUID must be 16 bytes")
        return (
            uuid_bytes[0:4][::-1] +
            uuid_bytes[4:6][::-1] +
            uuid_bytes[6:8][::-1] +
            uuid_bytes[8:16]
        )
    
    def _unpack_uuid(self, data: bytes) -> bytes:
        return (
            data[0:4][::-1] +
            data[4:6][::-1] +
            data[6:8][::-1] +
            data[8:16]
        )

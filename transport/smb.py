import struct
import os
from typing import Optional
from transport.tcp import TCPTransport
from transport.ntlm import NTLMAuth

class SMBTransport:
    SMB2_MAGIC = b"\xfeSMB"
    
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_IOCTL = 0x000b
    
    def __init__(self, host: str, username: str, password: str, domain: str, 
                 ntlm_hash: str = "", timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.ntlm_hash = ntlm_hash
        self.timeout = timeout
        
        self.tcp = TCPTransport(host, 445, timeout)
        self.ntlm = NTLMAuth(domain, username, password, ntlm_hash)
        
        self.session_id: int = 0
        self.tree_id: int = 0
        self.file_id: Optional[bytes] = None
        self.message_id: int = 0
        self.dialect: int = 0
        self.signing_required: bool = False
        self.session_key: Optional[bytes] = None
        
    def connect(self):
        self.tcp.connect()
        self._negotiate()
        self._session_setup()
        self._tree_connect(f"\\\\{self.host}\\IPC$")
        self._create_pipe("\\pipe\\lsass")
    
    def disconnect(self):
        if self.file_id:
            try:
                self._close_file()
            except:
                pass
        if self.tree_id:
            try:
                self._tree_disconnect()
            except:
                pass
        self.tcp.disconnect()
    
    def _next_message_id(self) -> int:
        mid = self.message_id
        self.message_id += 1
        return mid
    
    def _build_smb2_header(self, command: int, flags: int = 0, 
                           credit_charge: int = 1) -> bytearray:
        header = bytearray(64)
        header[0:4] = self.SMB2_MAGIC
        struct.pack_into("<H", header, 4, 64)
        struct.pack_into("<H", header, 6, credit_charge)
        struct.pack_into("<I", header, 8, 0)
        struct.pack_into("<H", header, 12, command)
        struct.pack_into("<H", header, 14, 31)
        struct.pack_into("<I", header, 16, flags)
        struct.pack_into("<I", header, 20, 0)
        struct.pack_into("<Q", header, 24, self._next_message_id())
        struct.pack_into("<I", header, 32, 0)
        struct.pack_into("<I", header, 36, 0)
        struct.pack_into("<Q", header, 40, self.session_id)
        struct.pack_into("<QQ", header, 48, 0, 0)
        return header
    
    def _send_smb2(self, data: bytes):
        pkt = struct.pack(">I", len(data)) + data
        self.tcp.send(pkt)
    
    def _recv_smb2(self) -> bytes:
        size_data = self.tcp.recv(4)
        size = struct.unpack(">I", size_data)[0]
        return self.tcp.recv(size)
    
    def _negotiate(self):
        header = self._build_smb2_header(self.SMB2_NEGOTIATE)
        
        neg = bytearray()
        neg.extend(struct.pack("<H", 36))
        neg.extend(struct.pack("<H", 2))
        neg.extend(struct.pack("<H", 0x0001))
        neg.extend(struct.pack("<H", 0))
        neg.extend(struct.pack("<I", 0))
        neg.extend(bytes(16))
        neg.extend(struct.pack("<H", 0x0202))
        neg.extend(struct.pack("<H", 0x0311))
        
        self._send_smb2(bytes(header) + bytes(neg))
        response = self._recv_smb2()
        
        if response[12:14] != b"\x00\x00":
            self.dialect = struct.unpack("<H", response[70:72])[0]
        else:
            self.dialect = 0x0202
    
    def _session_setup(self):
        neg_token = self.ntlm.get_negotiate_message()
        
        header = self._build_smb2_header(self.SMB2_SESSION_SETUP)
        
        setup = bytearray()
        setup.extend(struct.pack("<H", 25))
        setup.extend(struct.pack("<B", 0))
        setup.extend(struct.pack("<B", 0))
        setup.extend(struct.pack("<I", 0))
        setup.extend(struct.pack("<Q", 0))
        setup.extend(struct.pack("<H", 88))
        setup.extend(struct.pack("<H", len(neg_token)))
        
        self._send_smb2(bytes(header) + bytes(setup) + neg_token)
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0xc0000016:
            raise Exception(f"NTLM negotiate failed: 0x{status:08x}")
        
        self.session_id = struct.unpack("<Q", response[40:48])[0]
        
        sec_offset = struct.unpack("<H", response[68:70])[0]
        sec_length = struct.unpack("<H", response[70:72])[0]
        challenge = response[sec_offset:sec_offset + sec_length]
        
        auth_token = self.ntlm.process_challenge(challenge)
        
        header = self._build_smb2_header(self.SMB2_SESSION_SETUP)
        
        setup = bytearray()
        setup.extend(struct.pack("<H", 25))
        setup.extend(struct.pack("<B", 0))
        setup.extend(struct.pack("<B", 0))
        setup.extend(struct.pack("<I", 0))
        setup.extend(struct.pack("<Q", 0))
        setup.extend(struct.pack("<H", 88))
        setup.extend(struct.pack("<H", len(auth_token)))
        
        self._send_smb2(bytes(header) + bytes(setup) + auth_token)
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0:
            raise Exception(f"NTLM authentication failed: 0x{status:08x}")
        
        self.session_key = self.ntlm.get_session_key()
    
    def _tree_connect(self, share: str):
        header = self._build_smb2_header(self.SMB2_TREE_CONNECT)
        
        share_bytes = share.encode("utf-16-le")
        
        tree = bytearray()
        tree.extend(struct.pack("<H", 9))
        tree.extend(struct.pack("<H", 0))
        tree.extend(struct.pack("<H", 72))
        tree.extend(struct.pack("<H", len(share_bytes)))
        
        self._send_smb2(bytes(header) + bytes(tree) + share_bytes)
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0:
            raise Exception(f"Tree connect failed: 0x{status:08x}")
        
        self.tree_id = struct.unpack("<I", response[36:40])[0]
    
    def _tree_disconnect(self):
        header = self._build_smb2_header(self.SMB2_TREE_DISCONNECT)
        struct.pack_into("<I", header, 36, self.tree_id)
        
        tree = struct.pack("<HH", 4, 0)
        
        self._send_smb2(bytes(header) + tree)
        self._recv_smb2()
        self.tree_id = 0
    
    def _create_pipe(self, pipe: str):
        header = self._build_smb2_header(self.SMB2_CREATE)
        struct.pack_into("<I", header, 36, self.tree_id)
        
        pipe_bytes = pipe.encode("utf-16-le")
        
        create = bytearray(56)
        struct.pack_into("<H", create, 0, 57)
        create[2] = 0
        create[3] = 0x02
        struct.pack_into("<I", create, 4, 0x0007006c)
        struct.pack_into("<Q", create, 8, 0)
        struct.pack_into("<I", create, 24, 0x00000001)
        struct.pack_into("<I", create, 28, 0x00000040)
        struct.pack_into("<I", create, 32, 0x00000003)
        struct.pack_into("<I", create, 36, 0x00000002)
        struct.pack_into("<I", create, 40, 0)
        struct.pack_into("<H", create, 44, 120)
        struct.pack_into("<H", create, 46, len(pipe_bytes))
        struct.pack_into("<I", create, 48, 0)
        struct.pack_into("<I", create, 52, 0)
        
        self._send_smb2(bytes(header) + bytes(create) + pipe_bytes)
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0:
            raise Exception(f"Create pipe failed: 0x{status:08x}")
        
        self.file_id = response[128:144]
    
    def _close_file(self):
        if not self.file_id:
            return
        
        header = self._build_smb2_header(self.SMB2_CLOSE)
        struct.pack_into("<I", header, 36, self.tree_id)
        
        close = bytearray(24)
        struct.pack_into("<H", close, 0, 24)
        struct.pack_into("<H", close, 2, 0)
        close[8:24] = self.file_id
        
        self._send_smb2(bytes(header) + bytes(close))
        self._recv_smb2()
        self.file_id = None
    
    def send(self, data: bytes):
        if not self.file_id:
            raise Exception("Pipe not opened")
        
        header = self._build_smb2_header(self.SMB2_WRITE)
        struct.pack_into("<I", header, 36, self.tree_id)
        
        write = bytearray(48)
        struct.pack_into("<H", write, 0, 49)
        struct.pack_into("<H", write, 2, 112)
        struct.pack_into("<I", write, 4, len(data))
        struct.pack_into("<Q", write, 8, 0)
        write[16:32] = self.file_id
        struct.pack_into("<I", write, 32, 0)
        struct.pack_into("<I", write, 36, 0)
        struct.pack_into("<H", write, 40, 0)
        struct.pack_into("<H", write, 42, 0)
        struct.pack_into("<I", write, 44, 0)
        
        self._send_smb2(bytes(header) + bytes(write) + data)
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0:
            raise Exception(f"Write failed: 0x{status:08x}")
    
    def recv(self, size: int = 65536) -> bytes:
        if not self.file_id:
            raise Exception("Pipe not opened")
        
        header = self._build_smb2_header(self.SMB2_READ)
        struct.pack_into("<I", header, 36, self.tree_id)
        
        read = bytearray(48)
        struct.pack_into("<H", read, 0, 49)
        read[2] = 0
        read[3] = 0
        struct.pack_into("<I", read, 4, size)
        struct.pack_into("<Q", read, 8, 0)
        read[16:32] = self.file_id
        struct.pack_into("<I", read, 32, 0)
        struct.pack_into("<I", read, 36, 0)
        
        self._send_smb2(bytes(header) + bytes(read))
        response = self._recv_smb2()
        
        status = struct.unpack("<I", response[8:12])[0]
        if status != 0:
            raise Exception(f"Read failed: 0x{status:08x}")
        
        data_offset = struct.unpack("<B", response[64:65])[0]
        data_length = struct.unpack("<I", response[68:72])[0]
        
        return response[data_offset:data_offset + data_length]
    
    def recv_fragment(self) -> bytes:
        data = self.recv()
        if len(data) < 24:
            raise ValueError("Invalid RPC fragment")
        frag_len = struct.unpack("<H", data[8:10])[0]
        while len(data) < frag_len:
            data += self.recv()
        return data
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

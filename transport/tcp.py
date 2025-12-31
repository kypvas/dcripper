import socket
import struct
import ssl
from typing import Optional

class TCPTransport:
    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._connected = False
        
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.connect((self.host, self.port))
            self._connected = True
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")
    
    def disconnect(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.sock.close()
            self.sock = None
        self._connected = False
    
    def send(self, data: bytes) -> int:
        if not self._connected or not self.sock:
            raise ConnectionError("Not connected")
        return self.sock.sendall(data)
    
    def recv(self, size: int) -> bytes:
        if not self._connected or not self.sock:
            raise ConnectionError("Not connected")
        data = b""
        remaining = size
        while remaining > 0:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Connection closed by remote host")
            data += chunk
            remaining -= len(chunk)
        return data
    
    def recv_all(self) -> bytes:
        if not self._connected or not self.sock:
            raise ConnectionError("Not connected")
        data = b""
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except BlockingIOError:
                    break
        finally:
            self.sock.setblocking(True)
            self.sock.settimeout(self.timeout)
        return data
    
    def recv_fragment(self) -> bytes:
        header = self.recv(16)
        if len(header) < 10:
            raise ValueError("Invalid RPC header")
        frag_len = struct.unpack("<H", header[8:10])[0]
        if frag_len <= 16:
            return header
        body = self.recv(frag_len - 16)
        return header + body
    
    @property
    def is_connected(self) -> bool:
        return self._connected
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

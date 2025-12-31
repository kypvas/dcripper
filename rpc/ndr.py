import struct
from typing import List, Optional, Any, Tuple

class NDRSerializer:
    def __init__(self):
        self.buffer = bytearray()
        self._deferred = []
        self._referent_id = 0x20000
        
    def pack_uint8(self, value: int):
        self.buffer.append(value & 0xff)
        
    def pack_uint16(self, value: int):
        self.buffer.extend(struct.pack("<H", value))
        
    def pack_uint32(self, value: int):
        self.buffer.extend(struct.pack("<I", value))
        
    def pack_uint64(self, value: int):
        self.buffer.extend(struct.pack("<Q", value))
        
    def pack_int32(self, value: int):
        self.buffer.extend(struct.pack("<i", value))
        
    def pack_guid(self, guid: bytes):
        if len(guid) != 16:
            raise ValueError("GUID must be 16 bytes")
        self.buffer.extend(guid[0:4][::-1])
        self.buffer.extend(guid[4:6][::-1])
        self.buffer.extend(guid[6:8][::-1])
        self.buffer.extend(guid[8:16])
        
    def pack_guid_raw(self, guid: bytes):
        if len(guid) != 16:
            raise ValueError("GUID must be 16 bytes")
        self.buffer.extend(guid)
        
    def pack_bytes(self, data: bytes):
        self.buffer.extend(data)
        
    def pack_pointer(self, has_value: bool = True) -> int:
        if has_value:
            self._referent_id += 4
            ref_id = self._referent_id
            self.pack_uint32(ref_id)
            return ref_id
        else:
            self.pack_uint32(0)
            return 0
            
    def pack_conformant_array(self, data: bytes):
        self.pack_uint32(len(data))
        self.buffer.extend(data)
        self.align(4)
        
    def pack_conformant_varying_string(self, s: str):
        encoded = s.encode("utf-16-le") + b"\x00\x00"
        max_count = len(s) + 1
        actual_count = len(s) + 1
        self.pack_uint32(max_count)
        self.pack_uint32(0)
        self.pack_uint32(actual_count)
        self.buffer.extend(encoded)
        self.align(4)
        
    def pack_unicode_string(self, s: str):
        encoded = s.encode("utf-16-le") + b"\x00\x00"
        self.pack_uint32(len(s) + 1)
        self.pack_uint32(0)
        self.pack_uint32(len(s) + 1)
        self.buffer.extend(encoded)
        self.align(4)
        
    def align(self, boundary: int, pad_byte: int = 0x00):
        padding = (boundary - len(self.buffer) % boundary) % boundary
        self.buffer.extend(bytes([pad_byte]) * padding)
        
    def get_data(self) -> bytes:
        return bytes(self.buffer)
        
    def __len__(self) -> int:
        return len(self.buffer)


class NDRDeserializer:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        
    def unpack_uint8(self) -> int:
        value = self.data[self.offset]
        self.offset += 1
        return value
        
    def unpack_uint16(self) -> int:
        value = struct.unpack_from("<H", self.data, self.offset)[0]
        self.offset += 2
        return value
        
    def unpack_uint32(self) -> int:
        value = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return value
        
    def unpack_uint64(self) -> int:
        value = struct.unpack_from("<Q", self.data, self.offset)[0]
        self.offset += 8
        return value
        
    def unpack_int32(self) -> int:
        value = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        return value
        
    def unpack_guid(self) -> bytes:
        raw = self.data[self.offset:self.offset + 16]
        self.offset += 16
        return raw[0:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:16]
        
    def unpack_guid_raw(self) -> bytes:
        raw = self.data[self.offset:self.offset + 16]
        self.offset += 16
        return raw
        
    def unpack_bytes(self, length: int) -> bytes:
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value
        
    def unpack_pointer(self) -> int:
        return self.unpack_uint32()
        
    def unpack_conformant_array(self) -> bytes:
        count = self.unpack_uint32()
        data = self.unpack_bytes(count)
        self.align(4)
        return data
        
    def unpack_unicode_string(self) -> str:
        max_count = self.unpack_uint32()
        offset = self.unpack_uint32()
        actual_count = self.unpack_uint32()
        data = self.unpack_bytes(actual_count * 2)
        self.align(4)
        return data.decode("utf-16-le").rstrip("\x00")
        
    def align(self, boundary: int):
        padding = (boundary - self.offset % boundary) % boundary
        self.offset += padding
        
    def remaining(self) -> int:
        return len(self.data) - self.offset
        
    def peek(self, length: int) -> bytes:
        return self.data[self.offset:self.offset + length]
        
    def skip(self, length: int):
        self.offset += length

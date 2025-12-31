from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import struct

@dataclass
class DSNAME:
    struct_len: int = 0
    sid_len: int = 0
    guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    sid: bytes = b""
    string_name: str = ""
    
    def to_ndr(self) -> bytes:
        from rpc.ndr import NDRSerializer

        # Prepare string name - always include at least null terminator
        if self.string_name:
            name_bytes = (self.string_name + "\x00").encode("utf-16-le")
            name_char_count = len(self.string_name) + 1
        else:
            # Empty name - still needs null terminator per MS-DRSR spec
            name_bytes = b"\x00\x00"  # Just null in UTF-16
            name_char_count = 0  # NameLen is 0 for GUID-only lookups

        sid_bytes = self.sid if self.sid else b""
        sid_len = len(sid_bytes)

        # MaxCount for the conformant StringName array
        # For GUID-only lookups, NameLen=0 but we still have a null terminator
        max_count = name_char_count + 1 if name_char_count > 0 else 1

        ndr = NDRSerializer()

        # For NDR conformant arrays (StringName is [size_is(NameLen+1)]):
        # MaxCount comes BEFORE the structure data
        ndr.pack_uint32(max_count)

        # Calculate structLen: size of DSNAME structure including conformant array prefix
        # structLen = MaxCount(4) + structLen(4) + SidLen(4) + Guid(16) + NT4SID(28) + NameLen(4) + StringName
        struct_len = 4 + 4 + 4 + 16 + 28 + 4 + len(name_bytes)
        ndr.pack_uint32(struct_len)

        # SidLen
        ndr.pack_uint32(sid_len)

        # Guid (16 bytes) - in little-endian wire format
        ndr.pack_guid_raw(self.guid)

        # NT4SID (fixed 28 bytes regardless of SidLen)
        ndr.pack_bytes(sid_bytes)
        ndr.pack_bytes(b"\x00" * (28 - len(sid_bytes)))

        # NameLen (number of chars, not including null terminator)
        ndr.pack_uint32(name_char_count)

        # StringName (WCHAR array) - always at least null terminator
        ndr.pack_bytes(name_bytes)

        return ndr.get_data()
    
    @classmethod
    def from_dn(cls, dn: str) -> "DSNAME":
        return cls(string_name=dn)
    
    @classmethod
    def from_guid(cls, guid: bytes) -> "DSNAME":
        return cls(guid=guid)
    
    @classmethod
    def from_ndr(cls, data: bytes, offset: int = 0) -> tuple["DSNAME", int]:
        struct_len = struct.unpack_from("<I", data, offset)[0]
        sid_len = struct.unpack_from("<I", data, offset + 4)[0]
        guid = data[offset + 8:offset + 24]
        sid = data[offset + 24:offset + 24 + sid_len] if sid_len else b""
        
        name_offset = offset + 52
        name_char_count = struct.unpack_from("<I", data, name_offset)[0]
        name_offset += 4
        
        name_bytes = data[name_offset:name_offset + (name_char_count * 2)]
        string_name = name_bytes.decode("utf-16-le").rstrip("\x00")
        
        total_size = struct_len
        if total_size % 4:
            total_size += 4 - (total_size % 4)
        
        return cls(
            struct_len=struct_len,
            sid_len=sid_len,
            guid=guid,
            sid=sid,
            string_name=string_name
        ), offset + total_size


@dataclass
class DRS_EXTENSIONS:
    cb: int = 48
    dw_flags: int = 0x04000001
    site_guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    pid: int = 0
    repl_epoch: int = 0
    dw_flags_ext: int = 0
    config_obj_guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    dw_ext_caps: int = 0
    
    def to_ndr(self) -> bytes:
        from rpc.ndr import NDRSerializer
        
        ndr = NDRSerializer()
        
        ext_data = bytearray()
        ext_data.extend(struct.pack("<I", self.dw_flags))
        ext_data.extend(self.site_guid)
        ext_data.extend(struct.pack("<I", self.pid))
        ext_data.extend(struct.pack("<I", self.repl_epoch))
        ext_data.extend(struct.pack("<I", self.dw_flags_ext))
        ext_data.extend(self.config_obj_guid)
        ext_data.extend(struct.pack("<I", self.dw_ext_caps))
        
        ndr.pack_uint32(len(ext_data))
        ndr.pack_bytes(bytes(ext_data))
        
        return ndr.get_data()
    
    @classmethod
    def from_ndr(cls, data: bytes, offset: int = 0) -> tuple["DRS_EXTENSIONS", int]:
        cb = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        dw_flags = struct.unpack_from("<I", data, offset)[0]
        site_guid = data[offset + 4:offset + 20]
        pid = struct.unpack_from("<I", data, offset + 20)[0]
        repl_epoch = struct.unpack_from("<I", data, offset + 24)[0]
        
        return cls(
            cb=cb,
            dw_flags=dw_flags,
            site_guid=site_guid,
            pid=pid,
            repl_epoch=repl_epoch
        ), offset + cb


@dataclass
class SCHEMA_PREFIX_TABLE:
    prefix_count: int = 0
    prefixes: List[tuple] = field(default_factory=list)
    
    def to_ndr(self) -> bytes:
        from rpc.ndr import NDRSerializer
        
        ndr = NDRSerializer()
        ndr.pack_uint32(self.prefix_count)
        ndr.pack_pointer(self.prefix_count > 0)
        
        if self.prefix_count > 0:
            ndr.pack_uint32(self.prefix_count)
            for ndx, oid in self.prefixes:
                ndr.pack_uint32(ndx)
                ndr.pack_uint32(len(oid))
                ndr.pack_pointer(True)
            
            for ndx, oid in self.prefixes:
                ndr.pack_uint32(len(oid))
                ndr.pack_bytes(oid)
                ndr.align(4)
        
        return ndr.get_data()


@dataclass
class PARTIAL_ATTR_VECTOR:
    version: int = 1
    reserved1: int = 0
    attr_count: int = 0
    attrs: List[int] = field(default_factory=list)

    def to_ndr(self) -> bytes:
        from rpc.ndr import NDRSerializer

        ndr = NDRSerializer()

        # NDR conformant array: MaxCount comes BEFORE the structure
        ndr.pack_uint32(len(self.attrs))  # MaxCount for rgPartialAttr

        # Fixed fields
        ndr.pack_uint32(self.version)     # dwVersion
        ndr.pack_uint32(self.reserved1)   # dwReserved1
        ndr.pack_uint32(len(self.attrs))  # cAttrs

        # Array elements
        for attr in self.attrs:
            ndr.pack_uint32(attr)

        return ndr.get_data()


@dataclass
class ReplicationData:
    guid: bytes = b""
    sid: bytes = b""
    dn: str = ""
    sam_account_name: str = ""
    user_principal_name: str = ""
    nt_hash: bytes = b""
    lm_hash: bytes = b""
    nt_history: List[bytes] = field(default_factory=list)
    lm_history: List[bytes] = field(default_factory=list)
    supplemental_credentials: bytes = b""
    user_account_control: int = 0
    pwd_last_set: int = 0
    primary_group_id: int = 0
    service_principal_names: List[str] = field(default_factory=list)
    raw_attributes: Dict[int, bytes] = field(default_factory=dict)

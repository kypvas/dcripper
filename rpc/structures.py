from dataclasses import dataclass, field
from typing import Optional, List
import struct

@dataclass
class DSNAME:
    struct_len: int = 0
    sid_len: int = 0
    guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    sid: bytes = b""
    string_name: str = ""
    
    def to_ndr(self) -> bytes:
        from ndr import NDRSerializer
        
        name_bytes = self.string_name.encode("utf-16-le")
        name_len = len(self.string_name)
        
        ndr = NDRSerializer()
        ndr.pack_uint32(len(name_bytes) + 28 + len(self.sid))
        ndr.pack_uint32(len(self.sid))
        ndr.pack_guid_raw(self.guid)
        
        if self.sid:
            ndr.pack_bytes(self.sid)
            ndr.pack_bytes(b"\x00" * (28 - len(self.sid)))
        else:
            ndr.pack_bytes(b"\x00" * 28)
        
        ndr.pack_uint32(name_len)
        ndr.pack_bytes(name_bytes)
        ndr.align(4)
        
        return ndr.get_data()
    
    @classmethod
    def from_dn(cls, dn: str) -> "DSNAME":
        return cls(string_name=dn)
    
    @classmethod
    def from_guid(cls, guid: bytes) -> "DSNAME":
        return cls(guid=guid)


@dataclass
class DRS_EXTENSIONS_INT:
    cb: int = 0
    dw_flags: int = 0
    site_guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    pid: int = 0
    repl_epoch: int = 0
    dw_flags_ext: int = 0
    config_obj_guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    dw_ext_caps: int = 0
    
    def to_ndr(self) -> bytes:
        from ndr import NDRSerializer
        
        ndr = NDRSerializer()
        ndr.pack_uint32(48)
        ndr.pack_uint32(self.dw_flags)
        ndr.pack_guid_raw(self.site_guid)
        ndr.pack_uint32(self.pid)
        ndr.pack_uint32(self.repl_epoch)
        ndr.pack_uint32(self.dw_flags_ext)
        ndr.pack_guid_raw(self.config_obj_guid)
        ndr.pack_uint32(self.dw_ext_caps)
        
        return ndr.get_data()


@dataclass
class DRS_MSG_GETCHGREQ_V8:
    source_dsa: bytes = field(default_factory=lambda: b"\x00" * 16)
    invocation_id: bytes = field(default_factory=lambda: b"\x00" * 16)
    nc: Optional[DSNAME] = None
    usnvec_from: int = 0
    usnvec_to: int = 0
    utd_vec: Optional[bytes] = None
    flags: int = 0
    max_bytes: int = 0
    max_objects: int = 0
    extended_op: int = 0
    fsmo_guid: bytes = field(default_factory=lambda: b"\x00" * 16)
    ppartial_attr_set: Optional[List[int]] = None
    ppartial_attr_set_ex: Optional[List[int]] = None
    mapping_ctr: Optional[bytes] = None


@dataclass  
class UPTODATE_CURSOR_V1:
    source_dsa: bytes = field(default_factory=lambda: b"\x00" * 16)
    usn: int = 0


@dataclass
class UPTODATE_VECTOR_V1:
    version: int = 1
    reserved1: int = 0
    count: int = 0
    reserved2: int = 0
    cursors: List[UPTODATE_CURSOR_V1] = field(default_factory=list)

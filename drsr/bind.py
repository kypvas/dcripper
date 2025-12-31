import struct
import os
from typing import Tuple, Optional
from rpc.ndr import NDRSerializer, NDRDeserializer
from rpc.dcerpc import DCERPCClient
from drsr.structures import DRS_EXTENSIONS

DRSUAPI_DRS_BIND = 0

DRS_EXT_BASE = 0x00000001
DRS_EXT_ASYNCREPL = 0x00000002
DRS_EXT_REMOVEAPI = 0x00000004
DRS_EXT_MOVEREQ_V2 = 0x00000008
DRS_EXT_GETCHG_DEFLATE = 0x00000010
DRS_EXT_DCINFO_V1 = 0x00000020
DRS_EXT_RESTORE_USN_OPTIMIZATION = 0x00000040
DRS_EXT_ADDENTRY = 0x00000080
DRS_EXT_KCC_EXECUTE = 0x00000100
DRS_EXT_ADDENTRY_V2 = 0x00000200
DRS_EXT_LINKED_VALUE_REPLICATION = 0x00000400
DRS_EXT_DCINFO_V2 = 0x00000800
DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00001000
DRS_EXT_CRYPTO_BIND = 0x00002000
DRS_EXT_GET_REPL_INFO = 0x00004000
DRS_EXT_STRONG_ENCRYPTION = 0x00008000
DRS_EXT_DCINFO_VFFFFFFFF = 0x00010000
DRS_EXT_TRANSITIVE_MEMBERSHIP = 0x00020000
DRS_EXT_ADD_SID_HISTORY = 0x00040000
DRS_EXT_POST_BETA3 = 0x00080000
DRS_EXT_GETCHGREQ_V5 = 0x00100000
DRS_EXT_GETMEMBERSHIPS2 = 0x00200000
DRS_EXT_GETCHGREQ_V6 = 0x00400000
DRS_EXT_NONDOMAIN_NCS = 0x00800000
DRS_EXT_GETCHGREQ_V8 = 0x01000000
DRS_EXT_GETCHGREPLY_V5 = 0x02000000
DRS_EXT_GETCHGREPLY_V6 = 0x04000000
DRS_EXT_GETCHGREPLY_V9 = 0x00000100
DRS_EXT_WHISTLER_BETA3 = 0x08000000
DRS_EXT_W2K3_DEFLATE = 0x10000000
DRS_EXT_GETCHGREQ_V10 = 0x20000000
DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 = 0x40000000
DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3 = 0x80000000


class DRSBind:
    def __init__(self, rpc_client: DCERPCClient):
        self.rpc = rpc_client
        self.drs_handle: Optional[bytes] = None
        self.server_extensions: Optional[DRS_EXTENSIONS] = None
        
    def bind(self) -> Tuple[bytes, DRS_EXTENSIONS]:
        # Use NTDSAPI_CLIENT_GUID like Impacket does
        # e24d201a-4fd6-11d1-a3da-0000f875ae0d in binary form
        client_guid = bytes.fromhex('1a204de2d64fd111a3da0000f875ae0d')

        # Build DRS_EXTENSIONS_INT data (matches Impacket/secretsdump flags)
        # dwFlags, SiteObjGuid, Pid, dwReplEpoch, dwFlagsExt, ConfigObjGUID, dwExtCaps
        dw_flags = (
            DRS_EXT_GETCHGREQ_V6 |      # 0x00400000
            DRS_EXT_GETCHGREPLY_V6 |    # 0x04000000
            DRS_EXT_GETCHGREQ_V8 |      # 0x01000000
            DRS_EXT_STRONG_ENCRYPTION | # 0x00008000
            DRS_EXT_NONDOMAIN_NCS       # 0x00800000
        )

        ext_data = bytearray()
        ext_data.extend(struct.pack("<I", dw_flags))       # dwFlags
        ext_data.extend(b'\x00' * 16)                       # SiteObjGuid
        ext_data.extend(struct.pack("<I", 0))               # Pid
        ext_data.extend(struct.pack("<I", 0))               # dwReplEpoch
        ext_data.extend(struct.pack("<I", 0))               # dwFlagsExt
        ext_data.extend(b'\x00' * 16)                       # ConfigObjGUID
        ext_data.extend(struct.pack("<I", 0xffffffff))     # dwExtCaps (all caps)

        # cb is the count of bytes in the rgb field (per MS-DRSR)
        # Both MaxCount and cb should be 52 (the size of the ext_data)
        cb = len(ext_data)  # = 52

        ndr = NDRSerializer()

        # puuidClientDsa (PUUID = pointer to GUID)
        ndr.pack_pointer(True)           # Referent ID for PUUID
        ndr.pack_guid_raw(client_guid)   # GUID data (16 bytes)

        # pextClient (PDRS_EXTENSIONS = pointer to DRS_EXTENSIONS)
        ndr.pack_pointer(True)           # Referent ID for PDRS_EXTENSIONS
        ndr.pack_uint32(cb)              # MaxCount (conformant array size)
        ndr.pack_uint32(cb)              # cb field
        ndr.pack_bytes(bytes(ext_data))  # rgb data

        response = self.rpc.call(DRSUAPI_DRS_BIND, ndr.get_data())

        return self._parse_bind_response(response)
    
    def _parse_bind_response(self, response: bytes) -> Tuple[bytes, DRS_EXTENSIONS]:
        ndr = NDRDeserializer(response)

        # ppextServer (PDRS_EXTENSIONS = pointer to DRS_EXTENSIONS)
        ext_ptr = ndr.unpack_pointer()

        if ext_ptr:
            # MaxCount for conformant array (before structure fields)
            max_count = ndr.unpack_uint32()

            # cb field
            cb = ndr.unpack_uint32()

            # rgb data (conformant array)
            if cb >= 4:
                dw_flags = ndr.unpack_uint32()
            else:
                dw_flags = 0

            if cb >= 20:
                site_guid = ndr.unpack_bytes(16)
            else:
                site_guid = b'\x00' * 16

            if cb >= 24:
                pid = ndr.unpack_uint32()
            else:
                pid = 0

            if cb >= 28:
                repl_epoch = ndr.unpack_uint32()
            else:
                repl_epoch = 0

            # Skip any remaining extension data
            remaining = cb - 28
            if remaining > 0:
                ndr.skip(remaining)

            self.server_extensions = DRS_EXTENSIONS(
                cb=cb,
                dw_flags=dw_flags,
                site_guid=site_guid,
                pid=pid,
                repl_epoch=repl_epoch
            )
        else:
            self.server_extensions = DRS_EXTENSIONS()

        # phDrs (DRS_HANDLE = 20 bytes)
        drs_handle = ndr.unpack_bytes(20)
        self.drs_handle = drs_handle

        # ErrorCode (DWORD) - we should check this
        error_code = ndr.unpack_uint32()
        if error_code != 0:
            raise Exception(f"DRS_BIND failed with error: 0x{error_code:08x}")

        return self.drs_handle, self.server_extensions
    
    def get_handle(self) -> bytes:
        if not self.drs_handle:
            raise ValueError("Not bound - call bind() first")
        return self.drs_handle

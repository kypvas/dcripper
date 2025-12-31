"""DRSDomainControllerInfo implementation for getting DC metadata."""

import struct
from typing import Optional, Tuple
from rpc.ndr import NDRSerializer, NDRDeserializer
from rpc.dcerpc import DCERPCClient

DRSUAPI_DRS_DOMAIN_CONTROLLER_INFO = 16


class DRSDomainControllerInfo:
    """Get domain controller information including NtdsDsaObjectGuid."""

    def __init__(self, rpc_client: DCERPCClient, drs_handle: bytes):
        self.rpc = rpc_client
        self.drs_handle = drs_handle

    def get_dc_info(self, domain: str) -> Optional[bytes]:
        """Get NtdsDsaObjectGuid for the target DC.

        Args:
            domain: Domain name (e.g., "lab.local")

        Returns:
            NtdsDsaObjectGuid as 16 bytes, or None on failure
        """
        request = self._build_request(domain, info_level=2)
        response = self.rpc.call(DRSUAPI_DRS_DOMAIN_CONTROLLER_INFO, request)
        return self._parse_response(response)

    def _build_request(self, domain: str, info_level: int = 2) -> bytes:
        """Build DRS_MSG_DCINFOREQ_V1 request.

        Structure:
            hDrs (DRS_HANDLE = 20 bytes)
            dwInVersion (DWORD) = 1
            pmsgIn union tag (DWORD) = 1
            DRS_MSG_DCINFOREQ_V1:
                Domain (LPWSTR - pointer + conformant varying string)
                InfoLevel (DWORD)
        """
        ndr = NDRSerializer()

        # hDrs (DRS_HANDLE = 20 bytes)
        ndr.pack_bytes(self.drs_handle)

        # dwInVersion = 1
        ndr.pack_uint32(1)

        # pmsgIn union tag = 1 (for V1)
        ndr.pack_uint32(1)

        # DRS_MSG_DCINFOREQ_V1
        # Domain (LPWSTR - pointer to unicode string)
        ndr.pack_pointer(True)  # Referent ID

        # InfoLevel
        ndr.pack_uint32(info_level)

        # Now the actual string data (conformant varying string)
        ndr.pack_conformant_varying_string(domain)

        return ndr.get_data()

    def _parse_response(self, response: bytes) -> Optional[bytes]:
        """Parse DRS_MSG_DCINFOREPLY to extract NtdsDsaObjectGuid.

        For InfoLevel=2, response is DRS_MSG_DCINFOREPLY_V2 containing
        DS_DOMAIN_CONTROLLER_INFO_2W structures with NtdsDsaObjectGuid.
        """
        import os
        if os.environ.get('DEBUG_RPC'):
            print(f"[DEBUG] DCInfo response ({len(response)} bytes): {response[:100].hex()}...")

        ndr = NDRDeserializer(response)

        try:
            # pdwOutVersion (DWORD)
            version = ndr.unpack_uint32()

            # pmsgOut union switch/tag (DWORD) - should be 2 for V2
            switch_val = ndr.unpack_uint32()

            if switch_val != 2:
                # Unexpected response version
                return None

            # DRS_MSG_DCINFOREPLY_V2
            # cItems (DWORD)
            count = ndr.unpack_uint32()
            if count == 0:
                return None

            # rItems pointer (to array of DS_DOMAIN_CONTROLLER_INFO_2W)
            items_ptr = ndr.unpack_pointer()
            if not items_ptr:
                return None

            # Conformant array MaxCount
            items_count = ndr.unpack_uint32()

            # We need to parse DS_DOMAIN_CONTROLLER_INFO_2W structures
            # to find the NtdsDsaObjectGuid. The structure contains many
            # LPWSTR pointers followed by BOOLs and GUIDs.

            # First, read the fixed parts of all structures (pointers and fixed fields)
            # DS_DOMAIN_CONTROLLER_INFO_2W:
            #   NetbiosName (LPWSTR)
            #   DnsHostName (LPWSTR)
            #   SiteName (LPWSTR)
            #   SiteObjectName (LPWSTR)
            #   ComputerObjectName (LPWSTR)
            #   ServerObjectName (LPWSTR)
            #   NtdsDsaObjectName (LPWSTR)
            #   fIsPdc (BOOL = 4 bytes)
            #   fDsEnabled (BOOL = 4 bytes)
            #   fIsGc (BOOL = 4 bytes)
            #   SiteObjectGuid (GUID = 16 bytes)
            #   ComputerObjectGuid (GUID = 16 bytes)
            #   ServerObjectGuid (GUID = 16 bytes)
            #   NtdsDsaObjectGuid (GUID = 16 bytes)

            item_pointers = []
            for _ in range(items_count):
                # 7 LPWSTR pointers
                pointers = []
                for _ in range(7):
                    pointers.append(ndr.unpack_pointer())

                # 3 BOOLs (4 bytes each)
                is_pdc = ndr.unpack_uint32()
                ds_enabled = ndr.unpack_uint32()
                is_gc = ndr.unpack_uint32()

                # 4 GUIDs (16 bytes each)
                site_guid = ndr.unpack_bytes(16)
                computer_guid = ndr.unpack_bytes(16)
                server_guid = ndr.unpack_bytes(16)
                ntds_dsa_guid = ndr.unpack_bytes(16)

                item_pointers.append({
                    'string_ptrs': pointers,
                    'ntds_dsa_guid': ntds_dsa_guid
                })

            # Skip reading the actual string data - we only need the GUID
            # Return the first DC's NtdsDsaObjectGuid
            if item_pointers:
                return item_pointers[0]['ntds_dsa_guid']

            return None

        except Exception as e:
            import os
            if os.environ.get('DEBUG_RPC'):
                print(f"[DEBUG] DCInfo parse error: {e}")
            return None

import struct
from typing import List, Tuple, Optional
from rpc.ndr import NDRSerializer, NDRDeserializer
from rpc.dcerpc import DCERPCClient
from config import (
    DS_NAME_FORMAT_NT4_ACCOUNT, DS_NAME_FORMAT_FQDN_1779,
    DS_NAME_FORMAT_USER_PRINCIPAL, DS_NAME_FLAG_NO_FLAGS
)

DRSUAPI_DRS_CRACK_NAMES = 12


class DRSCrackNames:
    def __init__(self, rpc_client: DCERPCClient, drs_handle: bytes):
        self.rpc = rpc_client
        self.drs_handle = drs_handle
        
    def crack_name(
        self,
        name: str,
        format_offered: int = DS_NAME_FORMAT_NT4_ACCOUNT,
        format_desired: int = DS_NAME_FORMAT_FQDN_1779
    ) -> Optional[str]:
        results = self.crack_names([name], format_offered, format_desired)
        return results[0] if results else None
    
    def crack_names(
        self,
        names: List[str],
        format_offered: int = DS_NAME_FORMAT_NT4_ACCOUNT,
        format_desired: int = DS_NAME_FORMAT_FQDN_1779
    ) -> List[Optional[str]]:
        request = self._build_request(names, format_offered, format_desired)
        response = self.rpc.call(DRSUAPI_DRS_CRACK_NAMES, request)
        return self._parse_response(response)
    
    def _build_request(
        self,
        names: List[str],
        format_offered: int,
        format_desired: int
    ) -> bytes:
        ndr = NDRSerializer()

        # hDrs (DRS_HANDLE = 20 bytes)
        ndr.pack_bytes(self.drs_handle)

        # dwInVersion = 1
        ndr.pack_uint32(1)

        # pmsgIn (DRS_MSG_CRACKREQ union) - tag first
        ndr.pack_uint32(1)  # Union tag = 1 for V1

        # DRS_MSG_CRACKREQ_V1 structure
        ndr.pack_uint32(0)  # CodePage
        ndr.pack_uint32(0)  # LocaleId
        ndr.pack_uint32(0)  # dwFlags
        ndr.pack_uint32(format_offered)  # formatOffered
        ndr.pack_uint32(format_desired)  # formatDesired
        ndr.pack_uint32(len(names))  # cNames

        # rpNames (PLPWSTR_ARRAY = pointer to array of LPWSTR)
        ndr.pack_pointer(True)  # Referent ID for the array

        # Conformant array - MaxCount first
        ndr.pack_uint32(len(names))

        # Array of pointers to strings
        for _ in names:
            ndr.pack_pointer(True)

        # Now the actual string data (conformant varying strings)
        for name in names:
            ndr.pack_conformant_varying_string(name)

        return ndr.get_data()
    
    def _parse_response(self, response: bytes) -> List[Optional[str]]:
        import os
        if os.environ.get('DEBUG_RPC'):
            print(f"[DEBUG] CrackNames response ({len(response)} bytes): {response[:100].hex()}...")

        ndr = NDRDeserializer(response)

        results = []

        try:
            # pdwOutVersion (DWORD)
            version = ndr.unpack_uint32()

            # pmsgOut union switch/tag (DWORD)
            switch_val = ndr.unpack_uint32()

            # pResult pointer (DS_NAME_RESULTW*)
            result_ptr = ndr.unpack_pointer()
            if not result_ptr:
                return results

            # DS_NAME_RESULTW.cItems
            count = ndr.unpack_uint32()
            if count == 0:
                return results

            # DS_NAME_RESULTW.rItems pointer
            items_ptr = ndr.unpack_pointer()
            if not items_ptr:
                return results

            # Conformant array MaxCount
            items_actual_count = ndr.unpack_uint32()

            # Read all DS_NAME_RESULT_ITEMW structures first
            item_data = []
            for _ in range(items_actual_count):
                status = ndr.unpack_uint32()
                domain_ptr = ndr.unpack_pointer()
                name_ptr = ndr.unpack_pointer()
                item_data.append((status, domain_ptr, name_ptr))

            # Now read the string data
            for status, domain_ptr, name_ptr in item_data:
                if status != 0:
                    results.append(None)
                    continue

                if domain_ptr:
                    _ = ndr.unpack_unicode_string()

                if name_ptr:
                    name = ndr.unpack_unicode_string()
                    results.append(name)
                else:
                    results.append(None)

        except Exception as e:
            pass

        return results
    
    def get_domain_dn(self, domain_netbios: str) -> Optional[str]:
        result = self.crack_name(
            domain_netbios + "\\",
            DS_NAME_FORMAT_NT4_ACCOUNT,
            DS_NAME_FORMAT_FQDN_1779
        )
        return result
    
    def resolve_user_dn(self, username: str, domain: str) -> Optional[str]:
        full_name = f"{domain}\\{username}"
        return self.crack_name(
            full_name,
            DS_NAME_FORMAT_NT4_ACCOUNT,
            DS_NAME_FORMAT_FQDN_1779
        )

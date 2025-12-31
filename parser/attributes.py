import struct
from typing import Dict, Any, List, Optional
from drsr.structures import ReplicationData

class AttributeParser:
    ATTR_MAP = {
        0x90001: ("distinguishedName", "dn"),
        0x90008: ("userAccountControl", "int"),
        0x9001f: ("member", "dn_list"),
        0x90045: ("sAMAccountName", "string"),
        0x90048: ("objectGUID", "guid"),
        0x9004a: ("pwdLastSet", "filetime"),
        0x9005a: ("unicodePwd", "binary"),
        0x9005d: ("lmPwdHistory", "binary_list"),
        0x9005e: ("ntPwdHistory", "binary_list"),
        0x9007d: ("supplementalCredentials", "binary"),
        0x90092: ("objectSid", "sid"),
        0x90099: ("primaryGroupID", "int"),
        0x90290: ("userPrincipalName", "string"),
        0x90303: ("servicePrincipalName", "string_list"),
    }
    
    def __init__(self):
        self.prefix_table = {}
    
    def set_prefix_table(self, table: Dict[int, bytes]):
        self.prefix_table = table
    
    def parse_attribute(self, attr_type: int, value: bytes) -> tuple:
        attr_info = self.ATTR_MAP.get(attr_type)
        if not attr_info:
            return (f"unknown_{attr_type:x}", value)
        
        name, value_type = attr_info
        
        parsed_value = self._parse_value(value, value_type)
        return (name, parsed_value)
    
    def _parse_value(self, value: bytes, value_type: str) -> Any:
        if value_type == "string":
            try:
                return value.decode("utf-16-le").rstrip("\x00")
            except:
                return value.hex()
        elif value_type == "int":
            if len(value) >= 4:
                return struct.unpack("<I", value[:4])[0]
            return 0
        elif value_type == "filetime":
            if len(value) >= 8:
                return struct.unpack("<Q", value[:8])[0]
            return 0
        elif value_type == "guid":
            return value.hex() if len(value) == 16 else ""
        elif value_type == "sid":
            return value
        elif value_type == "binary":
            return value
        elif value_type == "binary_list":
            return [value[i:i+16] for i in range(0, len(value), 16) if i+16 <= len(value)]
        elif value_type == "string_list":
            try:
                return value.decode("utf-16-le").rstrip("\x00").split("\x00")
            except:
                return []
        elif value_type == "dn":
            try:
                return value.decode("utf-16-le").rstrip("\x00")
            except:
                return value.hex()
        elif value_type == "dn_list":
            try:
                return value.decode("utf-16-le").rstrip("\x00").split("\x00")
            except:
                return []
        else:
            return value


def extract_attributes(repl_data: ReplicationData) -> Dict[str, Any]:
    parser = AttributeParser()
    result = {}
    
    for attr_type, value in repl_data.raw_attributes.items():
        name, parsed = parser.parse_attribute(attr_type, value)
        result[name] = parsed
    
    result["guid"] = repl_data.guid.hex() if repl_data.guid else ""
    result["sid"] = repl_data.sid.hex() if repl_data.sid else ""
    result["sam_account_name"] = repl_data.sam_account_name
    result["user_principal_name"] = repl_data.user_principal_name
    
    return result

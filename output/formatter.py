from typing import Optional, List, Dict, Any
from drsr.structures import ReplicationData
from parser.sid import sid_to_string, get_rid_from_sid
from drsr.crypto import decrypt_nt_hash, decrypt_attribute_value

class OutputFormatter:
    def __init__(self, domain: str, session_key: Optional[bytes] = None):
        self.domain = domain
        self.session_key = session_key
    
    def format_user(self, data: ReplicationData, output_format: str = "hashcat") -> str:
        if output_format == "hashcat":
            return self._format_hashcat(data)
        elif output_format == "pwdump":
            return self._format_pwdump(data)
        elif output_format == "secretsdump":
            return self._format_secretsdump(data)
        elif output_format == "json":
            return self._format_json(data)
        else:
            return self._format_hashcat(data)
    
    def _format_hashcat(self, data: ReplicationData) -> str:
        username = data.sam_account_name or "unknown"
        rid = get_rid_from_sid(data.sid) if data.sid else 0
        
        nt_hash = self._get_nt_hash(data, rid)
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        
        return f"{self.domain}\\{username}:{rid}:{lm_hash}:{nt_hash}:::"
    
    def _format_pwdump(self, data: ReplicationData) -> str:
        username = data.sam_account_name or "unknown"
        rid = get_rid_from_sid(data.sid) if data.sid else 0
        
        nt_hash = self._get_nt_hash(data, rid)
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        
        return f"{username}:{rid}:{lm_hash}:{nt_hash}:::"
    
    def _format_secretsdump(self, data: ReplicationData) -> str:
        username = data.sam_account_name or "unknown"
        rid = get_rid_from_sid(data.sid) if data.sid else 0

        nt_hash = self._get_nt_hash(data, rid)
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"

        lines = []
        lines.append(f"{self.domain}\\{username}:{rid}:{lm_hash}:{nt_hash}:::")

        # TODO: Implement supplemental credentials decryption if needed
        # For now, just output the hash

        return "\n".join(lines)
    
    def _format_json(self, data: ReplicationData) -> str:
        import json
        
        username = data.sam_account_name or "unknown"
        rid = get_rid_from_sid(data.sid) if data.sid else 0
        
        result = {
            "domain": self.domain,
            "username": username,
            "rid": rid,
            "sid": sid_to_string(data.sid) if data.sid else "",
            "nt_hash": self._get_nt_hash(data, rid),
            "user_account_control": data.user_account_control,
            "upn": data.user_principal_name,
            "spns": data.service_principal_names,
        }
        
        return json.dumps(result, indent=2)
    
    def _get_nt_hash(self, data: ReplicationData, rid: int) -> str:
        if not data.nt_hash:
            return "31d6cfe0d16ae931b73c59d7e0c089c0"

        if self.session_key:
            try:
                # Use the correct decryption function from drsr.crypto
                decrypted = decrypt_nt_hash(data.nt_hash, self.session_key, rid)
                return decrypted.hex()
            except Exception as e:
                pass

        if len(data.nt_hash) == 16:
            return data.nt_hash.hex()

        return "31d6cfe0d16ae931b73c59d7e0c089c0"


def format_hash(nt_hash: bytes) -> str:
    if len(nt_hash) == 16:
        return nt_hash.hex()
    return ""


def format_secretsdump(
    domain: str,
    username: str,
    rid: int,
    nt_hash: str,
    lm_hash: str = "aad3b435b51404eeaad3b435b51404ee",
    cleartext: Optional[str] = None
) -> List[str]:
    lines = []
    lines.append(f"{domain}\\{username}:{rid}:{lm_hash}:{nt_hash}:::")
    
    if cleartext:
        lines.append(f"{domain}\\{username}:CLEARTEXT:{cleartext}")
    
    return lines

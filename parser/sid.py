import struct
from typing import Optional, Tuple

def parse_sid(sid_bytes: bytes) -> Optional[dict]:
    if not sid_bytes or len(sid_bytes) < 8:
        return None
    
    try:
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        
        authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
        
        sub_authorities = []
        offset = 8
        for _ in range(sub_auth_count):
            if offset + 4 > len(sid_bytes):
                break
            sub_auth = struct.unpack_from("<I", sid_bytes, offset)[0]
            sub_authorities.append(sub_auth)
            offset += 4
        
        return {
            "revision": revision,
            "authority": authority,
            "sub_authorities": sub_authorities
        }
    except Exception:
        return None


def sid_to_string(sid_bytes: bytes) -> str:
    parsed = parse_sid(sid_bytes)
    if not parsed:
        return ""
    
    sid_str = f"S-{parsed['revision']}-{parsed['authority']}"
    for sub_auth in parsed['sub_authorities']:
        sid_str += f"-{sub_auth}"
    
    return sid_str


def get_rid_from_sid(sid_bytes: bytes) -> int:
    parsed = parse_sid(sid_bytes)
    if not parsed or not parsed['sub_authorities']:
        return 0
    
    return parsed['sub_authorities'][-1]


def sid_from_string(sid_str: str) -> bytes:
    parts = sid_str.split("-")
    if len(parts) < 3 or parts[0] != "S":
        raise ValueError(f"Invalid SID string: {sid_str}")
    
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]
    
    sid = bytearray()
    sid.append(revision)
    sid.append(len(sub_authorities))
    sid.extend(authority.to_bytes(6, byteorder='big'))
    
    for sub_auth in sub_authorities:
        sid.extend(struct.pack("<I", sub_auth))
    
    return bytes(sid)


def get_domain_sid(user_sid: bytes) -> bytes:
    parsed = parse_sid(user_sid)
    if not parsed or len(parsed['sub_authorities']) < 1:
        return b""
    
    domain_sid = bytearray()
    domain_sid.append(parsed['revision'])
    domain_sid.append(len(parsed['sub_authorities']) - 1)
    domain_sid.extend(parsed['authority'].to_bytes(6, byteorder='big'))
    
    for sub_auth in parsed['sub_authorities'][:-1]:
        domain_sid.extend(struct.pack("<I", sub_auth))
    
    return bytes(domain_sid)

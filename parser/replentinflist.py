import struct
from typing import List, Dict, Any, Optional
from drsr.structures import ReplicationData

def parse_replication_response(data: bytes) -> List[ReplicationData]:
    results = []
    offset = 0
    
    try:
        while offset < len(data):
            obj, new_offset = parse_single_object(data, offset)
            if obj:
                results.append(obj)
            if new_offset <= offset:
                break
            offset = new_offset
    except Exception:
        pass
    
    return results


def parse_single_object(data: bytes, offset: int) -> tuple:
    result = ReplicationData()
    
    try:
        if offset + 20 > len(data):
            return None, len(data)
        
        next_ptr = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        obj_ptr = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        if not obj_ptr:
            return None, offset
        
        result.guid = data[offset:offset + 16]
        offset += 16
        
        sid_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        if sid_len > 0:
            result.sid = data[offset:offset + sid_len]
            offset += sid_len
        
        attr_count = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        for _ in range(attr_count):
            if offset + 12 > len(data):
                break
            
            attr_type = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            
            attr_len = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            
            attr_ptr = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            
            if attr_ptr and attr_len > 0:
                attr_value = data[offset:offset + attr_len]
                offset += attr_len
                
                padding = (4 - (attr_len % 4)) % 4
                offset += padding
                
                result.raw_attributes[attr_type] = attr_value
                _process_known_attribute(result, attr_type, attr_value)
        
        return result, offset
    
    except Exception:
        return None, len(data)


def _process_known_attribute(result: ReplicationData, attr_type: int, value: bytes):
    ATTRS = {
        0x9005a: "nt_hash",
        0x9005e: "nt_history",
        0x9005d: "lm_history",
        0x9007d: "supplemental_credentials",
        0x90092: "sid",
        0x90045: "sam_account_name",
        0x90290: "user_principal_name",
        0x90008: "user_account_control",
        0x9004a: "pwd_last_set",
        0x90099: "primary_group_id",
    }
    
    attr_name = ATTRS.get(attr_type)
    if not attr_name:
        return
    
    if attr_name == "nt_hash":
        result.nt_hash = value
    elif attr_name == "nt_history":
        result.nt_history = [value[i:i+16] for i in range(0, len(value), 16)]
    elif attr_name == "lm_history":
        result.lm_history = [value[i:i+16] for i in range(0, len(value), 16)]
    elif attr_name == "supplemental_credentials":
        result.supplemental_credentials = value
    elif attr_name == "sid":
        result.sid = value
    elif attr_name == "sam_account_name":
        try:
            result.sam_account_name = value.decode("utf-16-le").rstrip("\x00")
        except:
            pass
    elif attr_name == "user_principal_name":
        try:
            result.user_principal_name = value.decode("utf-16-le").rstrip("\x00")
        except:
            pass
    elif attr_name == "user_account_control":
        if len(value) >= 4:
            result.user_account_control = struct.unpack("<I", value[:4])[0]
    elif attr_name == "pwd_last_set":
        if len(value) >= 8:
            result.pwd_last_set = struct.unpack("<Q", value[:8])[0]
    elif attr_name == "primary_group_id":
        if len(value) >= 4:
            result.primary_group_id = struct.unpack("<I", value[:4])[0]

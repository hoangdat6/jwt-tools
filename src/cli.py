"""Command Line Interface for JWT Tool"""

import sys
import argparse
from pathlib import Path
import json

from .parser import JWTParser
from .verifier import JWTVerifier
from .cracker import JWTCracker, ProgressUpdate
from .forger import JWTForger


def analyze_command(args):
    """Handle analyze subcommand"""
    token = args.token
    
    # Read from file if specified
    if args.file:
        try:
            token = Path(args.file).read_text().strip()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    
    if not token:
        print("Error: No token provided", file=sys.stderr)
        return 1
    
    parser = JWTParser()
    
    try:
        analysis = parser.parse(token)
        output = parser.format_analysis(analysis, colors=not args.no_color)
        print(output)
        
        # Return non-zero if critical warnings found
        critical_warnings = [w for w in analysis.warnings if w.severity == 'critical']
        return 1 if critical_warnings else 0
        
    except ValueError as e:
        print(f"Error parsing JWT: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def verify_command(args):
    """Handle verify subcommand"""
    token = args.token
    key = args.key
    
    # Read token from file if specified
    if args.token_file:
        try:
            token = Path(args.token_file).read_text().strip()
        except Exception as e:
            print(f"Error reading token file: {e}", file=sys.stderr)
            return 1
    
    # Read key from file if specified
    if args.key_file:
        try:
            key = Path(args.key_file).read_text().strip()
        except Exception as e:
            print(f"Error reading key file: {e}", file=sys.stderr)
            return 1
    
    if not token:
        print("Error: No token provided", file=sys.stderr)
        return 1
    
    if not key:
        print("Error: No key provided", file=sys.stderr)
        return 1
    
    verifier = JWTVerifier()
    
    try:
        result = verifier.verify(token, key, algorithm=args.algorithm)
        
        # Format output
        from colorama import Fore, Style, init
        if not args.no_color:
            init()
        
        print("=" * 70)
        print("JWT SIGNATURE VERIFICATION")
        print("=" * 70)
        print()
        print(f"Algorithm: {result.algorithm}")
        
        if result.key_info:
            print(f"Key Info: {result.key_info}")
        
        print()
        
        if result.valid:
            status = "✓ VALID"
            if not args.no_color:
                status = Fore.GREEN + status + Style.RESET_ALL
            print(f"Status: {status}")
            print(f"Message: {result.message}")
            return 0
        else:
            status = "✗ INVALID"
            if not args.no_color:
                status = Fore.RED + status + Style.RESET_ALL
            print(f"Status: {status}")
            print(f"Message: {result.message}")
            return 1
        
    except Exception as e:
        print(f"Verification error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def crack_command(args):
    """Handle crack subcommand"""
    token = args.token
    
    # Read token from file if specified
    if args.token_file:
        try:
            token = Path(args.token_file).read_text().strip()
        except Exception as e:
            print(f"Error reading token file: {e}", file=sys.stderr)
            return 1
    
    if not token:
        print("Error: No token provided", file=sys.stderr)
        return 1
    
    # Prepare cracker
    workers = args.workers if args.workers else None
    cracker = JWTCracker(num_workers=workers)
    
    # Progress callback
    from colorama import Fore, Style, init
    if not args.no_color:
        init()
    
    def progress_callback(progress: ProgressUpdate):
        if args.quiet:
            return
        
        # Format progress message
        msg = f"\r[*] Attempts: {progress.attempts:,} | "
        msg += f"Speed: {progress.attempts_per_second:.0f} attempts/sec | "
        msg += f"Elapsed: {progress.elapsed_time:.1f}s"
        
        if progress.percentage:
            msg += f" | Progress: {progress.percentage:.1f}%"
        
        if progress.estimated_remaining:
            msg += f" | ETA: {progress.estimated_remaining:.1f}s"
        
        print(msg, end='', flush=True)
    
    # Start cracking
    print("=" * 70)
    print("JWT SECRET CRACKING")
    print("=" * 70)
    print()
    
    if args.wordlist:
        print(f"Wordlist: {args.wordlist}")
    if args.common or not args.wordlist:
        print("Using common secrets: Yes")
    print(f"Workers: {workers or 'auto'}")
    print()
    print("Starting brute-force attack...")
    print()
    
    try:
        result = cracker.crack(
            token=token,
            wordlist_path=args.wordlist,
            use_common=args.common or not args.wordlist,
            progress_callback=progress_callback if not args.quiet else None
        )
        
        # Clear progress line
        if not args.quiet:
            print()
        
        print()
        print("=" * 70)
        print("RESULT")
        print("=" * 70)
        print()
        
        if result.success:
            status = "✓ SECRET FOUND!"
            if not args.no_color:
                status = Fore.GREEN + status + Style.RESET_ALL
            
            print(f"Status: {status}")
            print(f"Secret: {result.secret}")
            print()
            print(f"Attempts: {result.attempts:,}")
            print(f"Time: {result.elapsed_time:.2f}s")
            print(f"Speed: {result.attempts_per_second:.0f} attempts/sec")
            
            # Save to file if requested
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(result.secret)
                    print(f"\nSecret saved to: {args.output}")
                except Exception as e:
                    print(f"\nWarning: Failed to save secret: {e}", file=sys.stderr)
            
            return 0
        else:
            status = "✗ Secret not found"
            if not args.no_color:
                status = Fore.RED + status + Style.RESET_ALL
            
            print(f"Status: {status}")
            print()
            print(f"Attempts: {result.attempts:,}")
            print(f"Time: {result.elapsed_time:.2f}s")
            print(f"Speed: {result.attempts_per_second:.0f} attempts/sec")
            print()
            print("Try a larger wordlist or ensure the token uses a weak secret.")
            
            return 1
        
    except FileNotFoundError as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nCracking interrupted by user.")
        return 130
    except Exception as e:
        print(f"\nError during cracking: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def forge_command(args):
    """Handle forge subcommand"""
    token = args.token
    
    # Read token from file if specified
    if args.token_file:
        try:
            token = Path(args.token_file).read_text().strip()
        except Exception as e:
            print(f"Error reading token file: {e}", file=sys.stderr)
            return 1
    
    if not token:
        print("Error: No token provided", file=sys.stderr)
        return 1
    
    forger = JWTForger()
    
    from colorama import Fore, Style, init
    if not args.no_color:
        init()
    
    print("=" * 70)
    print("JWT TOKEN FORGING")
    print("=" * 70)
    print()
    
    # Different forge modes
    if args.mode == 'none':
        # None algorithm attack
        modifications = {}
        if args.claims:
            try:
                modifications = json.loads(args.claims)
            except json.JSONDecodeError:
                print("Error: Invalid JSON for claims", file=sys.stderr)
                return 1
        
        result = forger.forge_none_algorithm(token, modifications)
        
    elif args.mode == 'modify':
        # Modify claims
        if not args.claims:
            print("Error: --claims required for modify mode", file=sys.stderr)
            return 1
        
        try:
            modifications = json.loads(args.claims)
        except json.JSONDecodeError:
            print("Error: Invalid JSON for claims", file=sys.stderr)
            return 1
        
        result = forger.forge_modify_claims(token, modifications, args.secret)
        
    elif args.mode == 'confusion':
        # Algorithm confusion
        if not args.public_key:
            print("Error: --public-key required for confusion mode", file=sys.stderr)
            return 1
        
        result = forger.forge_algorithm_confusion(token, args.public_key)
        
    elif args.mode == 'custom':
        # Custom token
        if not args.header or not args.payload:
            print("Error: --header and --payload required for custom mode", file=sys.stderr)
            return 1
        
        try:
            header = json.loads(args.header)
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("Error: Invalid JSON for header or payload", file=sys.stderr)
            return 1
        
        result = forger.forge_custom(header, payload, args.secret)
        
    elif args.mode == 'escalate':
        # Quick privilege escalation
        escalations = forger.get_common_escalations()
        
        if args.escalation_type not in escalations:
            print(f"Error: Unknown escalation type: {args.escalation_type}", file=sys.stderr)
            print(f"Available types: {', '.join(escalations.keys())}")
            return 1
        
        escalation = escalations[args.escalation_type]
        print(f"Attack: {escalation['name']}")
        print(f"Description: {escalation['description']}")
        print()
        
        result = forger.forge_modify_claims(
            token, 
            escalation['modifications'],
            args.secret
        )
    
    else:
        print(f"Error: Unknown forge mode: {args.mode}", file=sys.stderr)
        return 1
    
    # Display result
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print()
    
    if result.success:
        status = "✓ SUCCESS"
        if not args.no_color:
            status = Fore.GREEN + status + Style.RESET_ALL
        
        print(f"Status: {status}")
        print(f"Attack: {result.attack_type}")
        print(f"Message: {result.message}")
        print()
        print("Forged Token:")
        print(result.token)
        print()
        
        if result.header:
            print("New Header:")
            print(json.dumps(result.header, indent=2))
            print()
        
        if result.payload:
            print("New Payload:")
            print(json.dumps(result.payload, indent=2))
            print()
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(result.token)
                print(f"Token saved to: {args.output}")
            except Exception as e:
                print(f"Warning: Failed to save token: {e}", file=sys.stderr)
        
        return 0
    else:
        status = "✗ FAILED"
        if not args.no_color:
            status = Fore.RED + status + Style.RESET_ALL
        
        print(f"Status: {status}")
        print(f"Error: {result.message}")
        return 1


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='jwt-tool',
        description='JWT Security Analysis and Testing Tool'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.3.0'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Parse and analyze a JWT token'
    )
    analyze_parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to analyze'
    )
    analyze_parser.add_argument(
        '-f', '--file',
        help='Read token from file'
    )
    analyze_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Verify command
    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify JWT signature with a key'
    )
    verify_parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to verify'
    )
    verify_parser.add_argument(
        'key',
        nargs='?',
        help='Secret key or path to public key file'
    )
    verify_parser.add_argument(
        '-t', '--token-file',
        help='Read token from file'
    )
    verify_parser.add_argument(
        '-k', '--key-file',
        help='Read key from file'
    )
    verify_parser.add_argument(
        '-a', '--algorithm',
        help='Force specific algorithm (e.g., HS256, RS256)'
    )
    verify_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Crack command
    crack_parser = subparsers.add_parser(
        'crack',
        help='Brute-force crack JWT secret'
    )
    crack_parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to crack'
    )
    crack_parser.add_argument(
        '-t', '--token-file',
        help='Read token from file'
    )
    crack_parser.add_argument(
        '-w', '--wordlist',
        help='Path to wordlist file'
    )
    crack_parser.add_argument(
        '-c', '--common',
        action='store_true',
        default=True,
        help='Try common weak secrets (default: true)'
    )
    crack_parser.add_argument(
        '--no-common',
        action='store_false',
        dest='common',
        help='Skip common secrets'
    )
    crack_parser.add_argument(
        '--workers',
        type=int,
        help='Number of worker processes (default: CPU count)'
    )
    crack_parser.add_argument(
        '-o', '--output',
        help='Save found secret to file'
    )
    crack_parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    crack_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Forge command
    forge_parser = subparsers.add_parser(
        'forge',
        help='Forge/manipulate JWT tokens for security testing'
    )
    forge_parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to forge/modify'
    )
    forge_parser.add_argument(
        '-t', '--token-file',
        help='Read token from file'
    )
    forge_parser.add_argument(
        '-m', '--mode',
        choices=['none', 'modify', 'confusion', 'custom', 'escalate'],
        default='modify',
        help='Forge mode (default: modify)'
    )
    forge_parser.add_argument(
        '-c', '--claims',
        help='JSON object with claims to modify (e.g., \'{"role":"admin"}\')'
    )
    forge_parser.add_argument(
        '-s', '--secret',
        help='Secret to re-sign token'
    )
    forge_parser.add_argument(
        '--header',
        help='Custom header JSON (for custom mode)'
    )
    forge_parser.add_argument(
        '--payload',
        help='Custom payload JSON (for custom mode)'
    )
    forge_parser.add_argument(
        '--public-key',
        help='Public key for algorithm confusion attack'
    )
    forge_parser.add_argument(
        '--escalation-type',
        choices=['user_to_admin', 'elevate_permissions', 'change_user_id', 
                'extend_expiry', 'bypass_email_verification'],
        default='user_to_admin',
        help='Quick escalation type (for escalate mode)'
    )
    forge_parser.add_argument(
        '-o', '--output',
        help='Save forged token to file'
    )
    forge_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    if args.command == 'analyze':
        return analyze_command(args)
    elif args.command == 'verify':
        return verify_command(args)
    elif args.command == 'crack':
        return crack_command(args)
    elif args.command == 'forge':
        return forge_command(args)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

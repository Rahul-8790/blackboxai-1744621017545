#!/usr/bin/env python3
"""
Bug Bounty Hunting Toolkit
Main CLI interface

IMPORTANT: Only use this tool on targets you have explicit permission to test.
Unauthorized testing is illegal and unethical.
"""

import argparse
import sys
import os
from colorama import Fore, Style, init

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.scanner import BugBountyScanner
from backend.core.scope import ScopeManager
from backend.utils.logger import BugBountyLogger

init(autoreset=True)

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Bug Bounty Hunting Toolkit v1.0                   ║
║        Ethical Security Research Tool                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  IMPORTANT DISCLAIMER ⚠️{Style.RESET_ALL}

This tool is designed for AUTHORIZED security testing only.
You MUST have explicit permission to test any target.

{Fore.RED}Unauthorized testing is ILLEGAL and UNETHICAL.{Style.RESET_ALL}

By using this tool, you agree to:
  ✓ Only test targets you have permission to test
  ✓ Follow all bug bounty platform rules
  ✓ Respect rate limits and avoid service disruption
  ✓ Report findings responsibly
  ✓ Not exploit vulnerabilities beyond proof of concept

{Fore.GREEN}Compliant with: HackerOne, Bugcrowd, Intigriti, YesWeHack{Style.RESET_ALL}
"""
    print(banner)

def print_disclaimer():
    """Print legal disclaimer"""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print("LEGAL DISCLAIMER")
    print(f"{'='*60}{Style.RESET_ALL}")
    print("""
This tool is provided for educational and authorized security
testing purposes only. The developers assume no liability for
misuse or damage caused by this tool.

You are responsible for:
  • Obtaining proper authorization before testing
  • Following all applicable laws and regulations
  • Adhering to bug bounty program rules
  • Using the tool ethically and responsibly

Type 'I AGREE' to continue or 'exit' to quit:""")
    
    response = input("> ").strip()
    if response.upper() != "I AGREE":
        print(f"\n{Fore.RED}You must agree to the terms to use this tool.{Style.RESET_ALL}")
        sys.exit(0)
    
    print(f"\n{Fore.GREEN}✓ Terms accepted. Proceeding...{Style.RESET_ALL}\n")

def cmd_scan(args):
    """Execute scan command"""
    scanner = BugBountyScanner()
    
    # Load scope if provided
    if args.scope_file:
        if not scanner.load_scope_file(args.scope_file):
            print(f"{Fore.RED}Failed to load scope file{Style.RESET_ALL}")
            return
    else:
        # Set scope from command line
        scanner.set_scope([args.target])
    
    # Run scan
    scanner.scan_target(args.target, scan_type=args.type)

def cmd_scope(args):
    """Manage scope"""
    logger = BugBountyLogger()
    scope_manager = ScopeManager(logger=logger)
    
    if args.action == 'create':
        # Interactive scope creation
        print(f"\n{Fore.CYAN}Creating new scope configuration{Style.RESET_ALL}\n")
        
        program_name = input("Program name: ").strip()
        program_url = input("Program URL (optional): ").strip()
        
        scope_manager.program_name = program_name
        scope_manager.program_url = program_url
        
        print("\nEnter in-scope targets (one per line, empty line to finish):")
        while True:
            target = input("  > ").strip()
            if not target:
                break
            scope_manager.add_target(target, 'in')
        
        print("\nEnter out-of-scope targets (one per line, empty line to finish):")
        while True:
            target = input("  > ").strip()
            if not target:
                break
            scope_manager.add_target(target, 'out')
        
        # Save scope
        output_file = args.output or f"config/{program_name.lower().replace(' ', '_')}_scope.yaml"
        scope_manager.save_to_file(output_file)
    
    elif args.action == 'view':
        if args.file:
            scope_manager.load_from_file(args.file)
            scope_manager.display_scope()
        else:
            print(f"{Fore.RED}Please specify a scope file with --file{Style.RESET_ALL}")

def cmd_recon(args):
    """Run reconnaissance only"""
    scanner = BugBountyScanner()
    
    if args.scope_file:
        scanner.load_scope_file(args.scope_file)
    else:
        scanner.set_scope([args.target])
    
    scanner.scan_target(args.target, scan_type='recon')

def cmd_vuln(args):
    """Run vulnerability checks only"""
    scanner = BugBountyScanner()
    
    if args.scope_file:
        scanner.load_scope_file(args.scope_file)
    else:
        scanner.set_scope([args.target])
    
    scanner.scan_target(args.target, scan_type='vuln')

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Bug Bounty Hunting Toolkit - Ethical Security Research',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run full security scan')
    scan_parser.add_argument('target', help='Target domain or URL')
    scan_parser.add_argument('--type', choices=['full', 'recon', 'vuln'], 
                            default='full', help='Scan type (default: full)')
    scan_parser.add_argument('--scope-file', help='Path to scope YAML file')
    
    # Recon command
    recon_parser = subparsers.add_parser('recon', help='Run reconnaissance only')
    recon_parser.add_argument('target', help='Target domain or URL')
    recon_parser.add_argument('--scope-file', help='Path to scope YAML file')
    
    # Vuln command
    vuln_parser = subparsers.add_parser('vuln', help='Run vulnerability checks only')
    vuln_parser.add_argument('target', help='Target domain or URL')
    vuln_parser.add_argument('--scope-file', help='Path to scope YAML file')
    
    # Scope command
    scope_parser = subparsers.add_parser('scope', help='Manage scope configuration')
    scope_parser.add_argument('action', choices=['create', 'view'], 
                             help='Scope action')
    scope_parser.add_argument('--file', help='Scope file path')
    scope_parser.add_argument('--output', help='Output file path for create action')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Show disclaimer on first run
    if args.command in ['scan', 'recon', 'vuln']:
        print_disclaimer()
    
    # Execute command
    if args.command == 'scan':
        cmd_scan(args)
    elif args.command == 'recon':
        cmd_recon(args)
    elif args.command == 'vuln':
        cmd_vuln(args)
    elif args.command == 'scope':
        cmd_scope(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

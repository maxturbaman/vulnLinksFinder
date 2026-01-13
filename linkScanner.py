#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import time
import threading
from pathlib import Path
from colorama import Fore, Style, init

from vuln_checker.url_extractor import URLExtractor
from vuln_checker.http_checker import HTTPChecker
from vuln_checker.output_manager import OutputManager


def setup_colors():
    init(autoreset=True)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='VulnLinksFinder - Vulnerability Path Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://example.com"
  %(prog)s -l urls.txt -t 10
  %(prog)s -u "http://site1.com,http://site2.com" -o results.json -f json
  %(prog)s -l urls.txt --verbose --method GET --timeout 15
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-u', '--url',
        help='Single URL or comma-separated URLs (e.g., "http://site1.com,http://site2.com")'
    )
    input_group.add_argument(
        '-l', '--list',
        help='File with URL list (relative or absolute path)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (e.g., results/output.txt)',
        default=None
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=5,
        help='Number of parallel threads (default: 5)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'json', 'csv'],
        default='txt',
        help='Export format (default: txt)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout for requests in seconds (default: 10)'
    )
    parser.add_argument(
        '--method',
        choices=['GET', 'HEAD'],
        default='HEAD',
        help='HTTP method to use (default: HEAD, faster)'
    )
    parser.add_argument(
        '--user-agent',
        help='Custom User-Agent'
    )
    parser.add_argument(
        '--no-ssl',
        action='store_true',
        help='Disable SSL verification'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0,
        help='Delay between requests in seconds (default: 0)'
    )
    parser.add_argument(
        '--retries',
        type=int,
        default=1,
        help='Number of retries per URL (default: 1)'
    )
    parser.add_argument(
        '--follow-redirects',
        action='store_true',
        default=True,
        help='Follow redirects (default: true)'
    )
    parser.add_argument(
        '--proxy',
        help='Proxy to use (e.g., http://proxy:8080)'
    )
    parser.add_argument(
        '--filter',
        help='Filter by HTTP codes separated by comma (e.g., "200,404")'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose mode (show details)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (only errors/final results)'
    )
    parser.add_argument(
        '--vuln-file',
        default='Privat.txt',
        help='File with vulnerable paths (default: Privat.txt)'
    )
    parser.add_argument(
        '--all-results',
        action='store_true',
        help='Export all results, not just HTTP 200'
    )
    
    return parser.parse_args()


def main():
    setup_colors()
    
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    stop_event = threading.Event()
    
    def signal_handler(signum, frame):
        print(f"\n{Fore.YELLOW}⚠️  Stopping scan...{Style.RESET_ALL}")
        stop_event.set()
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        args = parse_arguments()
        
        if not args.quiet:
            print(f"\n{Fore.CYAN}{'='*80}")
            print(f"{Fore.CYAN}🔍 VulnLinksFinder v1.0.0 - Vulnerability Path Scanner")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Press Ctrl+C to stop the scan{Style.RESET_ALL}\n")
        
        if not args.quiet:
            print(f"{Fore.YELLOW}📥 Loading URLs...{Style.RESET_ALL}")
        
        project_root = Path(__file__).parent
        
        if args.url:
            urls = URLExtractor.from_urls(args.url)
            if not args.quiet:
                print(f"   ✓ {len(urls)} URL(s) from argument")
        else:
            urls = URLExtractor.from_file(args.list, str(project_root))
            if not args.quiet:
                print(f"   ✓ {len(urls)} URL(s) from file: {args.list}")
        
        urls = [URLExtractor.normalize_url(url) for url in urls]
        
        if not args.quiet:
            print(f"{Fore.YELLOW}📁 Loading vulnerable paths...{Style.RESET_ALL}")
        
        vuln_paths = URLExtractor.load_vuln_paths(args.vuln_file, str(project_root))
        
        if not vuln_paths:
            print(f"{Fore.RED}❌ No vulnerable paths loaded. Check Privat.txt{Style.RESET_ALL}")
            return 1
        
        if not args.quiet:
            print(f"   ✓ {len(vuln_paths)} vulnerable path(s) loaded")
        
        if not args.quiet:
            print(f"{Fore.YELLOW}⚙️  Configuring checker...{Style.RESET_ALL}")
        
        checker = HTTPChecker(
            timeout=args.timeout,
            retries=args.retries,
            method=args.method,
            user_agent=args.user_agent,
            verify_ssl=not args.no_ssl,
            delay=args.delay,
            follow_redirects=args.follow_redirects,
            proxy=args.proxy,
            verbose=args.verbose,
            stop_event=stop_event
        )
        
        total_checks = len(urls) * len(vuln_paths)
        if not args.quiet:
            print(f"   ✓ Will check {total_checks} URLs ({len(urls)} domain(s) × {len(vuln_paths)} path(s))")
        
        if not args.quiet:
            print(f"\n{Fore.YELLOW}🔗 Checking URLs...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")
        
        start_time = time.time()
        results = checker.check_urls_parallel(urls, vuln_paths, num_threads=args.threads)
        end_time = time.time()
        
        if stop_event.is_set():
            print(f"\n{Fore.YELLOW}⚠️  Scan cancelled by user{Style.RESET_ALL}")
            return 130
        
        if args.filter:
            try:
                status_codes = [int(c.strip()) for c in args.filter.split(',')]
                results = checker.filter_results(results, status_codes=status_codes)
                if not args.quiet:
                    print(f"{Fore.CYAN}Filtered by HTTP codes: {status_codes}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}❌ Error in filter format. Use: --filter '200,404,403'{Style.RESET_ALL}")
                return 1
        
        only_success = not args.all_results
        OutputManager.print_results(results, only_success=only_success, quiet=args.quiet)
        
        if not args.quiet:
            OutputManager.print_summary(results, start_time, end_time)
        
        if args.output:
            OutputManager.export_results(
                results,
                args.output,
                format=args.format,
                only_success=only_success
            )
        
        return 0
        
    except FileNotFoundError as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
        return 1
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Execution cancelled by user{Style.RESET_ALL}")
        return 130
    except Exception as e:
        print(f"{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

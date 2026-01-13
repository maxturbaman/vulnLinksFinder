import json
import csv
from typing import List, Dict
from datetime import datetime
import os
from colorama import Fore, Style


class OutputManager:
    
    @staticmethod
    def print_results(results: List[Dict], 
                     only_success: bool = True,
                     quiet: bool = False):
        if quiet:
            return
        
        display_results = results
        if only_success:
            display_results = [r for r in results if r['status_code'] == 200]
        
        if not display_results:
            print(f"\n{Fore.YELLOW}❌ No active vulnerabilities found (HTTP 200){Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.RED}{'='*80}")
        print(f"{Fore.RED}🔴 VULNERABILITIES FOUND: {len(display_results)}")
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}\n")
        
        for i, result in enumerate(display_results, 1):
            status_code = result['status_code']
            color = OutputManager._get_color_by_status(status_code)
            status_emoji = "✅" if status_code == 200 else "⚠️"
            
            print(f"{i}. {status_emoji} URL: {result['url']}")
            print(f"   {color}Status: {status_code}{Style.RESET_ALL} ({result['status']})")
            print(f"   Path: {result.get('vuln_path', 'N/A')}")
            print(f"   Time: {result['response_time']:.2f}s")
            
            if result.get('possibly_false_positive'):
                print(f"   {Fore.YELLOW}⚠️  Possible false positive (catch-all detected){Style.RESET_ALL}")
            
            if result['error']:
                print(f"   {Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
            
            print()
    
    @staticmethod
    def print_summary(results: List[Dict], start_time: float, end_time: float):
        total = len(results)
        success = len([r for r in results if r['status_code'] == 200])
        false_positives = len([r for r in results if r.get('possibly_false_positive')])
        errors = len([r for r in results if r['status'] == 'error'])
        timeouts = len([r for r in results if r['status'] == 'timeout'])
        
        elapsed = end_time - start_time
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📊 SUMMARY")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"Total checked: {total}")
        print(f"{Fore.GREEN}✅ HTTP 200 (Vulnerable): {success}{Style.RESET_ALL}")
        if false_positives > 0:
            print(f"{Fore.YELLOW}⚠️  Possible false positives: {false_positives}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Errors: {errors}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⏱  Timeouts: {timeouts}{Style.RESET_ALL}")
        print(f"⏱  Total time: {elapsed:.2f}s")
        print(f"⚡ Speed: {total/elapsed:.2f} URLs/s" if elapsed > 0 else "")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    @staticmethod
    def export_txt(results: List[Dict], 
                  output_file: str,
                  only_success: bool = True):
        display_results = results
        if only_success:
            display_results = [r for r in results if r['status_code'] == 200]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Vulnerability Report\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n\n")
            
            for i, result in enumerate(display_results, 1):
                f.write(f"{i}. URL: {result['url']}\n")
                f.write(f"   Status: {result['status_code']}\n")
                f.write(f"   Vulnerable path: {result.get('vuln_path', 'N/A')}\n")
                f.write(f"   Response time: {result['response_time']:.2f}s\n")
                
                if result['error']:
                    f.write(f"   Error: {result['error']}\n")
                
                f.write(f"\n")
            
            f.write(f"\n{'='*80}\n")
            f.write(f"Total: {len(display_results)}\n")
    
    @staticmethod
    def export_json(results: List[Dict],
                   output_file: str,
                   only_success: bool = True):
        display_results = results
        if only_success:
            display_results = [r for r in results if r['status_code'] == 200]
        
        data = {
            'generated': datetime.now().isoformat(),
            'total': len(display_results),
            'results': display_results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    @staticmethod
    def export_csv(results: List[Dict],
                  output_file: str,
                  only_success: bool = True):
        display_results = results
        if only_success:
            display_results = [r for r in results if r['status_code'] == 200]
        
        if not display_results:
            print("⚠️  No results to export")
            return
        
        fieldnames = ['url', 'status_code', 'status', 'vuln_path', 'response_time', 'error']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in display_results:
                writer.writerow({
                    'url': result['url'],
                    'status_code': result['status_code'],
                    'status': result['status'],
                    'vuln_path': result.get('vuln_path', ''),
                    'response_time': f"{result['response_time']:.2f}",
                    'error': result['error'] or ''
                })
    
    @staticmethod
    def export_results(results: List[Dict],
                      output_file: str,
                      format: str = 'txt',
                      only_success: bool = True):
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', 
                   exist_ok=True)
        
        if format.lower() == 'json':
            OutputManager.export_json(results, output_file, only_success)
        elif format.lower() == 'csv':
            OutputManager.export_csv(results, output_file, only_success)
        else:
            OutputManager.export_txt(results, output_file, only_success)
        
        print(f"{Fore.GREEN}✅ Results exported to: {output_file}{Style.RESET_ALL}")
    
    @staticmethod
    def _get_color_by_status(status_code: int) -> str:
        if status_code == 200:
            return Fore.GREEN
        elif status_code == 404:
            return Fore.RED
        elif status_code in [301, 302, 303, 307, 308]:
            return Fore.CYAN
        elif status_code in [403, 401, 405, 410]:
            return Fore.YELLOW
        elif status_code >= 500:
            return Fore.MAGENTA
        else:
            return Fore.WHITE

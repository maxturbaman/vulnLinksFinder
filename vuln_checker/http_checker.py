import requests
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import time
import threading
from colorama import Fore, Style
import hashlib


class HTTPChecker:
    
    DEFAULT_TIMEOUT = 10
    DEFAULT_RETRIES = 1
    DEFAULT_METHOD = "HEAD"
    
    def __init__(self, 
                 timeout: int = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES,
                 method: str = DEFAULT_METHOD,
                 user_agent: str = None,
                 verify_ssl: bool = True,
                 delay: float = 0,
                 follow_redirects: bool = True,
                 proxy: str = None,
                 verbose: bool = False,
                 stop_event: threading.Event = None):
        self.timeout = timeout
        self.retries = retries
        self.method = method.upper()
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.stop_event = stop_event or threading.Event()
        
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.catch_all_patterns = {}
    
    def detect_catch_all(self, base_url: str) -> Dict:
        test_paths = [
            '/xyzabc123_notexist_' + str(int(time.time())) + '.php',
            '/zzz_impossible_' + str(int(time.time())) + '.txt',
            '/nonexistent_' + hashlib.md5(str(time.time()).encode()).hexdigest()[:8] + '.jsp'
        ]
        
        results = []
        content_hashes = []
        
        for test_path in test_paths:
            try:
                test_url = base_url.rstrip('/') + test_path
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                    proxies=self.proxies,
                    stream=True
                )
                
                content_hash = hashlib.md5(response.content).hexdigest()
                content_hashes.append(content_hash)
                results.append({
                    'path': test_path,
                    'status': response.status_code,
                    'content_hash': content_hash,
                    'content_length': len(response.content)
                })
            except Exception as e:
                results.append({'path': test_path, 'status': 'error', 'error': str(e)[:50]})
        
        unique_hashes = len(set([r.get('content_hash') for r in results if 'content_hash' in r]))
        all_200 = all(r.get('status') == 200 for r in results)
        
        is_catch_all = all_200 and unique_hashes == 1
        
        return {
            'base_url': base_url,
            'is_catch_all': is_catch_all,
            'test_results': results,
            'all_return_200': all_200,
            'unique_responses': unique_hashes
        }
    
    
    def check_url(self, url: str) -> Dict:
        if self.stop_event.is_set():
            return {
                'url': url,
                'status_code': None,
                'status': 'cancelled',
                'response_time': 0,
                'error': 'Scan cancelled by user'
            }
        
        result = {
            'url': url,
            'status_code': None,
            'status': 'unknown',
            'response_time': 0,
            'error': None
        }
        
        for attempt in range(self.retries):
            try:
                start_time = time.time()
                
                if self.method == "HEAD":
                    response = requests.head(
                        url,
                        headers=self.headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=self.follow_redirects,
                        proxies=self.proxies
                    )
                else:  # GET
                    response = requests.get(
                        url,
                        headers=self.headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=self.follow_redirects,
                        proxies=self.proxies,
                        stream=True
                    )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                result['status_code'] = response.status_code
                result['response_time'] = response_time
                result['status'] = 'ok'
                result['possibly_false_positive'] = False
                
                base_url = '/'.join(url.split('/')[:3])
                if base_url in self.catch_all_patterns:
                    if self.catch_all_patterns[base_url]['is_catch_all']:
                        result['possibly_false_positive'] = True
                
                if self.verbose:
                    color = self._get_color_by_status(response.status_code)
                    print(f"{color}  ✓ {url} -> {response.status_code} ({response_time:.2f}s){Style.RESET_ALL}")
                
                return result
                
            except requests.Timeout:
                result['status'] = 'timeout'
                result['error'] = f'Timeout ({self.timeout}s)'
                if self.verbose and attempt == self.retries - 1:
                    print(f"{Fore.YELLOW}  ⏱ {url} -> Timeout{Style.RESET_ALL}")
            except requests.ConnectionError as e:
                result['status'] = 'error'
                result['error'] = f'Connection error: {str(e)[:50]}'
                if self.verbose and attempt == self.retries - 1:
                    print(f"{Fore.RED}  ✗ {url} -> Connection error{Style.RESET_ALL}")
            except Exception as e:
                result['status'] = 'error'
                result['error'] = f'Error: {str(e)[:50]}'
                if self.verbose and attempt == self.retries - 1:
                    print(f"{Fore.RED}  ✗ {url} -> Error{Style.RESET_ALL}")
            
            if attempt < self.retries - 1:
                time.sleep(0.5)
        
        return result
    
    def check_urls_parallel(self, 
                           urls: List[str],
                           vuln_paths: set,
                           base_urls: List[str] = None,
                           num_threads: int = 5) -> List[Dict]:
        if base_urls is None:
            base_urls = urls
        
        print(f"\n{Fore.CYAN}Testing for catch-all patterns...{Style.RESET_ALL}")
        for base_url in base_urls:
            if base_url not in self.catch_all_patterns:
                detection_result = self.detect_catch_all(base_url)
                self.catch_all_patterns[base_url] = detection_result
                
                if detection_result['is_catch_all']:
                    print(f"{Fore.YELLOW}⚠️  WARNING: {base_url} appears to have catch-all behavior{Style.RESET_ALL}")
                    print(f"   All test paths returned 200 with identical content")
                else:
                    print(f"{Fore.GREEN}✓ {base_url} - Normal behavior (no catch-all detected){Style.RESET_ALL}")
        
        print()
        
        
        urls_to_check = []
        for base_url in base_urls:
            for vuln_path in vuln_paths:
                full_url = urljoin(base_url, vuln_path)
                urls_to_check.append((full_url, vuln_path))
        
        results = []
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {}
            
            for full_url, vuln_path in urls_to_check:
                if self.stop_event.is_set():
                    break
                    
                future = executor.submit(self.check_url, full_url)
                futures[future] = vuln_path
                
                if self.delay > 0:
                    time.sleep(self.delay)
            
            for future in as_completed(futures):
                result = future.result()
                result['vuln_path'] = futures[future]
                results.append(result)
        
        return results
    
    def filter_results(self, 
                      results: List[Dict],
                      status_codes: List[int] = None,
                      statuses: List[str] = None) -> List[Dict]:
        filtered = results
        
        if status_codes:
            filtered = [r for r in filtered if r['status_code'] in status_codes]
        
        if statuses:
            filtered = [r for r in filtered if r['status'] in statuses]
        
        return filtered
    
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

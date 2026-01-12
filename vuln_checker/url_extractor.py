import os
from pathlib import Path
from typing import List, Set


class URLExtractor:
    
    @staticmethod
    def from_urls(urls_string: str) -> List[str]:
        urls = [url.strip() for url in urls_string.split(',')]
        return [url for url in urls if url]
    
    @staticmethod
    def from_file(file_path: str, project_root: str = None) -> List[str]:
        if not os.path.isabs(file_path) and project_root:
            possible_paths = [
                os.path.join(project_root, file_path),
                file_path
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    file_path = path
                    break
            else:
                raise FileNotFoundError(
                    f"File not found: {file_path}\n"
                    f"Searched in: {', '.join(possible_paths)}"
                )
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        urls.append(url)
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        urls.append(url)
        
        return urls
    
    @staticmethod
    def load_vuln_paths(privat_file_path: str = "Privat.txt", 
                        project_root: str = None) -> Set[str]:
        try:
            paths = URLExtractor.from_file(privat_file_path, project_root)
            return set(paths)
        except FileNotFoundError:
            print(f"⚠️  Vulnerable paths file not found: {privat_file_path}")
            return set()
    
    @staticmethod
    def normalize_url(url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        return url.rstrip('/')

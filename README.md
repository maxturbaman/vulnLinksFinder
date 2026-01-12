# VulnLinksFinder

**Professional tool for vulnerability path scanning on websites**

Automatically verifies if the vulnerable paths contained in `Privat.txt` actually exist on a website, notifying those that respond with HTTP 200 status code.

## 🚀 Features

- ✅ Parallel URL verification (multi-threading)
- ✅ Support for multiple sites simultaneously
- ✅ HTTP methods: GET and HEAD (HEAD faster)
- ✅ Automatic retries
- ✅ Configurable timeout
- ✅ Export to TXT, JSON and CSV
- ✅ Filtering by HTTP status codes
- ✅ Proxy support
- ✅ SSL/TLS control
- ✅ Customizable User-Agent
- ✅ Verbose and quiet modes
- ✅ Detailed execution statistics

## 📋 Requirements

- Python 3.8+
- pip

## ⚙️ Installation

1. **Clone or download the project**
```bash
cd d:\!PROJECTS\tools\vulnLinksFinder
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

## 📖 Usage

### General Syntax
```bash
python linkScanner.py [-u URL | -l FILE] [options]
```

### Basic Examples

**Verify a single URL:**
```bash
python linkScanner.py -u "http://example.com"
```

**Verify multiple URLs:**
```bash
python linkScanner.py -u "http://site1.com,http://site2.com,http://site3.com"
```

**Verify from file:**
```bash
python linkScanner.py -l urls.txt
```

**Export results:**
```bash
python linkScanner.py -u "http://example.com" -o results.txt
```

### Detailed Options

#### Input (Required - use one of these)

| Option | Description |
|--------|-------------|
| `-u, --url URL` | Single URL or comma-separated URLs |
| `-l, --list FILE` | File with URL list (one per line) |

#### Output and Format

| Option | Description | Default |
|--------|-------------|----------|
| `-o, --output FILE` | File to export results | No export |
| `-f, --format {txt,json,csv}` | Export format | txt |
| `--all-results` | Export all results (not just HTTP 200) | Only 200 |

#### Performance

| Option | Description | Default |
|--------|-------------|----------|
| `-t, --threads N` | Number of parallel threads | 5 |
| `--timeout N` | Timeout for requests (seconds) | 10 |
| `--delay N` | Delay between requests (seconds) | 0 |
| `--retries N` | Retries per URL | 1 |
| `--method {GET,HEAD}` | HTTP method | HEAD |

#### HTTP Configuration

| Option | Description |
|--------|-------------|
| `--user-agent TEXT` | Custom User-Agent |
| `--no-ssl` | Disable SSL/TLS verification |
| `--follow-redirects` | Follow redirects | 
| `--proxy URL` | Proxy to use (e.g., http://proxy:8080) |

#### Filtering and Display

| Option | Description |
|--------|-------------|
| `--filter CODES` | Filter by HTTP codes separated by comma (e.g., "200,404") |
| `-v, --verbose` | Verbose mode (show details during execution) |
| `-q, --quiet` | Quiet mode (only final results) |

#### File Configuration

| Option | Description | Default |
|--------|-------------|----------|
| `--vuln-file FILE` | File with vulnerable paths | Privat.txt |

## 📊 Advanced Examples

### 1. Fast verification with multiple threads
```bash
python linkScanner.py -l urls.txt -t 20 --method HEAD
```

### 2. Export to JSON with all results
```bash
python linkScanner.py -u "http://example.com" -o results.json -f json --all-results
```

### 3. Verification with proxy and retries
```bash
python linkScanner.py -l urls.txt --proxy "http://proxy:8080" --retries 3 -o results.csv -f csv
```

### 4. Verification with custom filter (find 200, 403 and 404)
```bash
python linkScanner.py -u "http://example.com" --filter "200,403,404" -o results.txt --all-results
```

### 5. Verbose verification with delay between requests
```bash
python linkScanner.py -l urls.txt -v --delay 0.5 --timeout 15
```

### 6. Ignore SSL errors
```bash
python linkScanner.py -u "https://example.com" --no-ssl
```

### 7. Use GET method (slower but more reliable)
```bash
python linkScanner.py -l urls.txt --method GET --timeout 20
```

## 📁 File Structure

```
vulnLinksFinder/
├── linkScanner.py             # Main file
├── requirements.txt           # Dependencies
├── README.md                  # This file
├── Privat.txt                 # Vulnerable paths (included file)
├── run.bat                    # Windows batch script
├── run.sh                     # Linux/Mac shell script
├── vuln_checker/
│   ├── __init__.py
│   ├── url_extractor.py       # URL and path loading
│   ├── http_checker.py        # HTTP verification
│   └── output_manager.py      # Result export
└── results/                   # Directory to save results
    ├── output.txt
    ├── results.json
    └── results.csv
```

## 📝 URL File Format

Create a `urls.txt` file with URLs (one per line):

```
http://site1.com
http://site2.com
https://site3.org
site4.com
```

URLs will be normalized automatically (http:// will be added if needed).

## 📋 Output Formats

### TXT
```
Vulnerability Report
Date: 2026-01-12 15:30:45
================================================================================

1. URL: http://example.com/shell.php
   Status: 200
   Vulnerable path: shell.php
   Response time: 0.25s

2. URL: http://example.com/admin.php
   Status: 200
   Vulnerable path: admin.php
   Response time: 0.18s
```

### JSON
```json
{
  "generated": "2026-01-12T15:30:45.123456",
  "total": 2,
  "results": [
    {
      "url": "http://example.com/shell.php",
      "status_code": 200,
      "status": "ok",
      "vuln_path": "shell.php",
      "response_time": 0.25,
      "error": null
    }
  ]
}
```

### CSV
```csv
url,status_code,status,vuln_path,response_time,error
http://example.com/shell.php,200,ok,shell.php,0.25,
http://example.com/admin.php,200,ok,admin.php,0.18,
```

## 🔍 Result Interpretation

| Code | Meaning |
|------|----------|
| 200 | ✅ **VULNERABLE** - Resource found and accessible |
| 301/302 | 🔄 Redirect (automatically followed) |
| 401/403 | 🔒 Access denied (exists but not accessible) |
| 404 | ❌ Not found |
| 500 | ⚠️ Server error |
| timeout | ⏱️ No response within time limit |
| error | ❌ Connection error |

## ⚡ Performance Tips

1. **Increase threads for many URLs:**
   ```bash
   python linkScanner.py -l urls.txt -t 50
   ```

2. **Use HEAD instead of GET (faster):**
   ```bash
   python linkScanner.py -l urls.txt --method HEAD
   ```

3. **Reduce timeout if experiencing slow responses:**
   ```bash
   python linkScanner.py -l urls.txt --timeout 5
   ```

4. **Use quiet mode to avoid slowdown:**
   ```bash
   python linkScanner.py -l urls.txt -q -o results.json
   ```

## 🔐 Security Considerations

- ⚠️ **Legal use**: Only use on sites you have permission to audit
- 🛡️ **Respect rate limits**: Use `--delay` to avoid saturating servers
- 🔒 **SSL**: Disable SSL verification only when necessary
- 🔑 **Proxies**: Use anonymous proxies if auditing third-party sites
- 📝 **Logs**: Results contain vulnerable URLs - keep them secure

## 🐛 Troubleshooting

**Error: "File not found: Privat.txt"**
- Make sure `Privat.txt` is in the project root directory

**Error: "Module not found"**
- Run: `pip install -r requirements.txt`

**URLs taking too long to verify**
- Increase threads: `-t 20`
- Reduce timeout: `--timeout 5`
- Use HEAD method: `--method HEAD`

**No vulnerabilities found**
- Verify URLs are correct: use `-v` for verbose
- Check connectivity: `ping domain.com`
- Try disabling SSL: `--no-ssl`

## 📚 Dependencies

- `requests`: HTTP library
- `urllib3`: HTTP support
- `colorama`: Terminal colors (Windows compatible)

## 📄 License

Security auditing project. Responsible use only.

## ✨ Version

**v1.0.0** - 2026-01-12

---

**Created with ❤️ for ethical security audits**

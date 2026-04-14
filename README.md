# Static Code Security Analyzer

A Python-based static analysis tool that scans source code for common security vulnerabilities. Built for CMPE 279 (Software Security Technologies) at San José State University.

## What It Does

The analyzer combines two detection layers:

- **Bandit** — industry-standard Python security linter
- **Custom AST checks** — purpose-built detectors using Python's Abstract Syntax Tree module that catch patterns Bandit misses

Every finding is assigned a severity score (HIGH / MEDIUM / LOW) and a fix recommendation. Results are printed to the terminal and saved as a report file.

## Vulnerabilities Detected

| Category | Examples |
|---|---|
| SQL Injection | String concatenation, f-strings, `%` formatting in `cursor.execute()` |
| Hardcoded Secrets | API keys, passwords, tokens, AWS credentials in variable assignments |
| Weak Cryptography | MD5 / SHA1 used for password hashing |
| Shell Injection | `os.system()`, `subprocess` with `shell=True` |
| Unsafe Deserialization | `pickle.load()` on untrusted data |
| Code Execution | `eval()`, `exec()` on user-supplied input |

## Project Structure

```
static_analyzer/
├── analyzer.py               # Main entry point
├── scorer.py                 # Severity scoring and normalization
├── reporter.py               # Terminal output and report file generation
├── checks/
│   ├── sql_injection.py      # AST-based SQL injection detection
│   ├── hardcoded_secrets.py  # Secret and weak hash detection
│   └── input_validation.py   # Shell injection, eval, pickle detection
└── samples/
    ├── vuln_db.py            # Intentionally vulnerable: SQL injection
    ├── vuln_auth.py          # Intentionally vulnerable: hardcoded secrets
    └── vuln_input.py         # Intentionally vulnerable: unsafe input handling
```

## Setup

```bash
# Clone the repo
git clone https://github.com/tromedo/279_Static_Analyzer.git
cd 279-static-analyzer

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# Install dependencies
pip install bandit
```

## Usage

```bash
# Scan a single file
python3 analyzer.py samples/vuln_db.py

# Scan a directory
python3 analyzer.py samples/

# Scan with custom output path
python3 analyzer.py samples/ --output my_report.txt
```

## Sample Output

```
======================================================================
  STATIC CODE SECURITY ANALYZER — REPORT
  Generated: 2026-04-14 16:42:13
======================================================================
  Files scanned : 3
  Total findings: 23
  HIGH    : 10
  MEDIUM  : 7
  LOW     : 6
======================================================================

  [1] HIGH  |  vuln_auth.py  |  Line 8  |  CUSTOM-SECRET
      Hardcoded secret detected in variable 'API_KEY'
      FIX: Load secrets from environment variables using os.environ.get() or a secrets manager

  [2] HIGH  |  vuln_input.py  |  Line 10  |  CUSTOM-INPUT
      os.system() with potentially unsanitized input — shell injection risk
      FIX: Use subprocess.run() with a list of arguments and shell=False
```

## Real-World Validation: Scrapy

We ran the analyzer against [Scrapy](https://github.com/scrapy/scrapy) — a production Python web scraping framework with 50,000+ GitHub stars used by companies worldwide.

```bash
git clone https://github.com/scrapy/scrapy --depth=1
python3 analyzer.py scrapy/ --output scrapy_report.txt
```

### Results

| Severity | Count |
|---|---|
| HIGH | 39 |
| MEDIUM | 28 |
| LOW | 4,868 |
| **Total** | **4,935** |
| Files scanned | 445 |

### Notable HIGH Findings in Production Code

| File | Line | Finding | Source |
|---|---|---|---|
| `engine.py` | 35 | `eval()` in the core crawling engine | Custom |
| `spiderstate.py` | 44 | `pickle.load()` for spider state persistence | Custom |
| `pqueues.py` | 36 | MD5 used in priority queue hashing | Bandit |
| `request.py` | 94 | SHA1 used for HTTP request fingerprinting | Bandit |
| `test_proxy_connect.py` | 20 | Hardcoded proxy credentials | Custom |

> Several of the HIGH findings in Scrapy were caught **exclusively by our custom AST checks** and were not flagged by Bandit alone — demonstrating the added value of the custom detection layer.

## Detection Sources

Each finding is tagged with its source:

- `bandit` — flagged by the Bandit linter
- `custom` — flagged by our AST-based checks only

This distinction matters: our custom checks caught SQL injection via f-strings and `%` formatting, hardcoded secrets by variable name pattern, and unsafe deserialization — patterns that Bandit either misses or rates differently.

## Course Context

**Course:** CMPE 279 — Software Security Technologies  
**Institution:** San José State University  
**Instructor:** Prof. Ammar Rayes  


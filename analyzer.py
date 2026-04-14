#!/usr/bin/env python3
"""
analyzer.py - Static Code Analysis Tool for Security Flaws
CMPE 279 Final Project

Usage:
    python analyzer.py <file_or_directory> [--output report.txt]

Examples:
    python analyzer.py samples/vuln_db.py
    python analyzer.py samples/
    python analyzer.py samples/ --output my_report.txt
"""

import ast
import sys
import os
import json
import argparse
import subprocess

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from checks import sql_injection, hardcoded_secrets, input_validation
from scorer import normalize_bandit_finding, tag_custom_finding, sort_findings
from reporter import print_report, save_report

CUSTOM_CHECKS = [sql_injection, hardcoded_secrets, input_validation]


def run_bandit(filepath):
    """Run bandit on a file and return parsed findings."""
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", filepath],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        return [normalize_bandit_finding(issue) for issue in data.get("results", [])]
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def run_custom_checks(filepath):
    """Parse the file with AST and run all custom checks."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"  [!] Could not parse {filepath}: {e}")
        return []

    findings = []
    for check_module in CUSTOM_CHECKS:
        results = check_module.check(tree, filepath)
        for r in results:
            findings.append(tag_custom_finding(r))
    return findings


def collect_python_files(path):
    """Return a list of .py files from a file or directory path."""
    if os.path.isfile(path):
        return [path] if path.endswith(".py") else []
    py_files = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return sorted(py_files)


def deduplicate(findings):
    """Remove duplicate findings (same file, line, and id)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f["filename"], f["line"], f["id"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze(path, output_path="security_report.txt"):
    files = collect_python_files(path)
    if not files:
        print(f"  [!] No Python files found at: {path}")
        sys.exit(1)

    print(f"\n  Scanning {len(files)} file(s)...")
    all_findings = []

    for filepath in files:
        # Skip the tool's own files
        if os.path.abspath(filepath).startswith(os.path.abspath(os.path.dirname(__file__))) and \
           "samples" not in filepath:
            continue

        bandit_findings = run_bandit(filepath)
        custom_findings = run_custom_checks(filepath)
        all_findings.extend(bandit_findings)
        all_findings.extend(custom_findings)

    all_findings = deduplicate(all_findings)
    all_findings = sort_findings(all_findings)

    print_report(all_findings, files)
    save_report(all_findings, files, output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Static Code Analysis Tool for Security Flaws — CMPE 279"
    )
    parser.add_argument("target", help="Python file or directory to scan")
    parser.add_argument("--output", default="security_report.txt", help="Output report file path")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"  [!] Path not found: {args.target}")
        sys.exit(1)

    analyze(args.target, args.output)


if __name__ == "__main__":
    main()

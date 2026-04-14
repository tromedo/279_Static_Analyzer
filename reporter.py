"""
reporter.py - Formats and outputs the security analysis report.
Prints a color-coded terminal report and saves a plain-text version to disk.
"""

import os
from datetime import datetime
from scorer import summarize, colorize

DIVIDER = "=" * 70
SUBDIV  = "-" * 70


def print_report(all_findings, scanned_files):
    summary = summarize(all_findings)
    total = len(all_findings)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{DIVIDER}")
    print("  STATIC CODE SECURITY ANALYZER — REPORT")
    print(f"  Generated: {timestamp}")
    print(DIVIDER)
    print(f"  Files scanned : {len(scanned_files)}")
    print(f"  Total findings: {total}")
    print(f"  HIGH    : {all_findings and summary['HIGH'] or 0}")
    print(f"  MEDIUM  : {all_findings and summary['MEDIUM'] or 0}")
    print(f"  LOW     : {all_findings and summary['LOW'] or 0}")
    print(DIVIDER)

    if not all_findings:
        print("\n  No vulnerabilities detected.\n")
        return

    for i, f in enumerate(all_findings, 1):
        sev_display = colorize(f["severity"])
        print(f"\n  [{i}] {sev_display}  |  {os.path.basename(f['filename'])}  |  Line {f['line']}  |  {f['id']}")
        print(f"      {f['description']}")
        print(f"      \033[92mFIX:\033[0m {f['fix']}")

    print(f"\n{DIVIDER}\n")


def save_report(all_findings, scanned_files, output_path="security_report.txt"):
    summary = summarize(all_findings)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(DIVIDER)
    lines.append("  STATIC CODE SECURITY ANALYZER — REPORT")
    lines.append(f"  Generated: {timestamp}")
    lines.append(DIVIDER)
    lines.append(f"  Files scanned : {len(scanned_files)}")
    lines.append(f"  Total findings: {len(all_findings)}")
    lines.append(f"  HIGH    : {summary['HIGH']}")
    lines.append(f"  MEDIUM  : {summary['MEDIUM']}")
    lines.append(f"  LOW     : {summary['LOW']}")
    lines.append(DIVIDER)

    if not all_findings:
        lines.append("\n  No vulnerabilities detected.")
    else:
        for i, f in enumerate(all_findings, 1):
            lines.append(f"\n[{i}] {f['severity']}  |  {os.path.basename(f['filename'])}  |  Line {f['line']}  |  {f['id']}")
            lines.append(f"    Description : {f['description']}")
            lines.append(f"    Fix         : {f['fix']}")
            lines.append(f"    Source      : {f['source']}")

    lines.append(f"\n{DIVIDER}")

    with open(output_path, "w") as out:
        out.write("\n".join(lines))

    print(f"  Report saved to: {output_path}\n")

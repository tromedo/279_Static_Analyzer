"""
scorer.py - Assigns and normalizes severity scores for findings.
Merges findings from bandit and custom AST checks into a unified format.
"""

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_COLORS = {
    "HIGH":   "\033[91m",  # Red
    "MEDIUM": "\033[93m",  # Yellow
    "LOW":    "\033[94m",  # Blue
}
RESET = "\033[0m"


def normalize_bandit_severity(bandit_severity):
    """Map bandit severity strings to our unified HIGH/MEDIUM/LOW scale."""
    mapping = {
        "HIGH":   "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW":    "LOW",
        "UNDEFINED": "LOW",
    }
    return mapping.get(bandit_severity.upper(), "LOW")


def normalize_bandit_finding(issue):
    """Convert a bandit issue dict into our unified finding format."""
    return {
        "id": f"B-{issue.get('test_id', 'UNKNOWN')}",
        "line": issue.get("line_number", 0),
        "filename": issue.get("filename", "unknown"),
        "description": issue.get("issue_text", "No description"),
        "severity": normalize_bandit_severity(issue.get("issue_severity", "LOW")),
        "fix": issue.get("issue_cwe", {}).get("link", "See bandit documentation for remediation guidance"),
        "source": "bandit"
    }


def tag_custom_finding(finding):
    """Tag a custom AST finding with its source."""
    finding["source"] = "custom"
    return finding


def sort_findings(findings):
    """Sort findings by severity (HIGH first) then by line number."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["line"]))


def summarize(findings):
    """Return a count breakdown by severity."""
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in summary:
            summary[sev] += 1
    return summary


def colorize(severity):
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{severity}{RESET}"

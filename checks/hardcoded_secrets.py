import ast
import re

FINDING_ID = "CUSTOM-SECRET"

# Patterns that suggest a variable holds a secret
SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_]?key|token|credential|aws|private[_]?key|auth)",
    re.IGNORECASE
)

# Patterns that suggest the value is a real secret (not a placeholder)
PLACEHOLDER_PATTERNS = re.compile(
    r"(your[_\-]|<|>|\.\.\.|example|placeholder|changeme|xxx|none|empty|todo)",
    re.IGNORECASE
)

WEAK_HASH_CALLS = {"md5", "sha1"}


def check(tree, filename):
    findings = []
    visitor = SecretsVisitor(filename)
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings


class SecretsVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                varname = target.id
                if SECRET_PATTERNS.search(varname):
                    # Check if the value is a non-empty string constant
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) > 4 and not PLACEHOLDER_PATTERNS.search(val):
                            self.findings.append({
                                "id": FINDING_ID,
                                "line": node.lineno,
                                "filename": self.filename,
                                "description": f"Hardcoded secret detected in variable '{varname}'",
                                "severity": "HIGH",
                                "fix": "Load secrets from environment variables using os.environ.get() or a secrets manager"
                            })
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect use of weak hashing algorithms: hashlib.md5(), hashlib.sha1()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in WEAK_HASH_CALLS:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": f"Weak hashing algorithm '{node.func.attr}' used — not suitable for passwords",
                        "severity": "MEDIUM",
                        "fix": "Use bcrypt, argon2, or hashlib.pbkdf2_hmac for password hashing"
                    })
        self.generic_visit(node)

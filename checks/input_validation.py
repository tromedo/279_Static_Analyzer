import ast

FINDING_ID = "CUSTOM-INPUT"

DANGEROUS_CALLS = {
    "eval": {
        "description": "Use of eval() on potentially unsanitized input — allows arbitrary code execution",
        "severity": "HIGH",
        "fix": "Replace eval() with a safe parser (e.g., ast.literal_eval for data, or explicit logic)"
    },
    "exec": {
        "description": "Use of exec() — executes arbitrary Python code, extreme risk if input is user-controlled",
        "severity": "HIGH",
        "fix": "Remove exec() — redesign to avoid dynamic code execution entirely"
    },
}

DANGEROUS_MODULES = {
    "pickle": {
        "attr": "load",
        "description": "Unsafe deserialization with pickle.load() — can execute arbitrary code on load",
        "severity": "HIGH",
        "fix": "Use json or a schema-validated format instead of pickle for untrusted data"
    },
}


def check(tree, filename):
    findings = []
    visitor = InputValidationVisitor(filename)
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings


class InputValidationVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def visit_Call(self, node):
        # Check for eval() and exec()
        if isinstance(node.func, ast.Name):
            fname = node.func.id
            if fname in DANGEROUS_CALLS:
                info = DANGEROUS_CALLS[fname]
                self.findings.append({
                    "id": FINDING_ID,
                    "line": node.lineno,
                    "filename": self.filename,
                    "description": info["description"],
                    "severity": info["severity"],
                    "fix": info["fix"]
                })

        # Check for os.system() — shell injection risk
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system" and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os":
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": "os.system() with potentially unsanitized input — shell injection risk",
                        "severity": "HIGH",
                        "fix": "Use subprocess.run() with a list of arguments and shell=False"
                    })

            # Check for subprocess with shell=True
            if node.func.attr in ("call", "run", "Popen"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.findings.append({
                            "id": FINDING_ID,
                            "line": node.lineno,
                            "filename": self.filename,
                            "description": "subprocess called with shell=True — exposes system to shell injection",
                            "severity": "HIGH",
                            "fix": "Pass arguments as a list and set shell=False (the default)"
                        })

            # Check for pickle.load()
            if node.func.attr == "load" and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "pickle":
                    info = DANGEROUS_MODULES["pickle"]
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": info["description"],
                        "severity": info["severity"],
                        "fix": info["fix"]
                    })

        self.generic_visit(node)

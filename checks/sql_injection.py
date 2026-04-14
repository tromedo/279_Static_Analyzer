import ast

FINDING_ID = "CUSTOM-SQL"

def check(tree, filename):
    """
    Detect SQL injection patterns using AST analysis.
    Looks for string concatenation or formatting passed to cursor.execute().
    """
    findings = []
    visitor = SQLInjectionVisitor(filename)
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings


class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def visit_Call(self, node):
        # Look for cursor.execute(...) calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                # Check for string concatenation (BinOp with Add)
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": "SQL query built with string concatenation — high risk of SQL injection",
                        "severity": "HIGH",
                        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (val,))"
                    })
                # Check for f-string (JoinedStr)
                elif isinstance(arg, ast.JoinedStr):
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": "SQL query built with f-string — high risk of SQL injection",
                        "severity": "HIGH",
                        "fix": "Use parameterized queries instead of f-strings in SQL statements"
                    })
                # Check for % formatting (BinOp with Mod)
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                    self.findings.append({
                        "id": FINDING_ID,
                        "line": node.lineno,
                        "filename": self.filename,
                        "description": "SQL query built with % string formatting — high risk of SQL injection",
                        "severity": "HIGH",
                        "fix": "Use parameterized queries instead of % formatting in SQL statements"
                    })
        self.generic_visit(node)

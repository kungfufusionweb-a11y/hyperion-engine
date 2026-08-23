"""Hyperion Security Engine — AST-based static analysis scanner."""

from __future__ import annotations

import ast
import re
from typing import Any

__all__ = ["scan_source"]

_SECRET_NAME_PATTERN = re.compile(
    r"(api[_-]?key|access[_-]?key|secret|password|passwd|pwd|token)",
    re.IGNORECASE,
)

_SQL_SINK_NAMES = {"execute", "executemany", "raw"}

_DANGEROUS_BUILTINS = {"eval", "exec"}

_DANGEROUS_DOTTED = {
    "os.system",
    "pickle.loads",
}

_SUBPROCESS_SHELL_FUNCS = {
    "run",
    "Popen",
    "call",
    "check_output",
    "check_call",
}


def _dotted_name(node: ast.expr) -> str | None:
    """Resolve a dotted name like 'os.system' or 'cursor.execute' from an AST node."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_literal_string(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _make_finding(
    filename: str,
    node: ast.AST,
    pattern_type: str,
    confidence: str,
    snippet: str,
) -> dict[str, Any]:
    return {
        "file": filename,
        "line_number": getattr(node, "lineno", 1),
        "column": getattr(node, "col_offset", 0),
        "snippet": snippet,
        "pattern_type": pattern_type,
        "confidence": confidence,
    }


class _VulnerabilityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str]) -> None:
        self.filename = filename
        self._lines = source_lines
        self.findings: list[dict[str, Any]] = []
        self._tainted_sql_vars: set[str] = set()

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()
        return ""

    # --- Hardcoded secrets ---
    def _check_secret_assignment(
        self, target: ast.expr, value: ast.expr, node: ast.AST
    ) -> None:
        if not _is_literal_string(value):
            return
        if not value.value:  # skip empty string placeholders
            return
        if isinstance(target, ast.Name):
            if _SECRET_NAME_PATTERN.search(target.id):
                self.findings.append(
                    _make_finding(
                        self.filename,
                        node,
                        "hardcoded_secret",
                        "high",
                        self._snippet(node.lineno),
                    )
                )
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                if isinstance(elt, ast.Name) and _SECRET_NAME_PATTERN.search(elt.id):
                    self.findings.append(
                        _make_finding(
                            self.filename,
                            node,
                            "hardcoded_secret",
                            "high",
                            self._snippet(node.lineno),
                        )
                    )

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1:
            self._check_secret_assignment(node.targets[0], node.value, node)
            if isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if self._is_risky_sql_build(node.value):
                    self._tainted_sql_vars.add(name)
                else:
                    self._tainted_sql_vars.discard(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self._check_secret_assignment(node.target, node.value, node)
        self.generic_visit(node)

    def _check_param_defaults(
        self, args: ast.arguments, defaults: list[ast.expr], offset: int
    ) -> None:
        for i, default in enumerate(defaults):
            idx = len(args.args) - len(defaults) + i
            if 0 <= idx < len(args.args):
                arg = args.args[idx]
                if _is_literal_string(default) and default.value:
                    if _SECRET_NAME_PATTERN.search(arg.arg):
                        self.findings.append(
                            _make_finding(
                                self.filename,
                                default,
                                "hardcoded_secret",
                                "high",
                                self._snippet(default.lineno),
                            )
                        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_param_defaults(node.args, node.args.defaults, 0)
        for kw_default, arg in zip(node.args.kw_defaults, node.args.kwonlyargs):
            if kw_default and _is_literal_string(kw_default) and kw_default.value:
                if _SECRET_NAME_PATTERN.search(arg.arg):
                    self.findings.append(
                        _make_finding(
                            self.filename,
                            kw_default,
                            "hardcoded_secret",
                            "high",
                            self._snippet(kw_default.lineno),
                        )
                    )
        saved_taint = self._tainted_sql_vars
        self._tainted_sql_vars = set()
        try:
            self.generic_visit(node)
        finally:
            self._tainted_sql_vars = saved_taint

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def _is_risky_sql_build(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.JoinedStr):
            return True
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return True
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
        ):
            return True
        return False

    # --- Calls ---
    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql_injection(node)
        self._check_dangerous_call(node)
        self._check_yaml_load(node)
        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        if not name:
            return
        sink = name.split(".")[-1]
        if sink not in _SQL_SINK_NAMES:
            return

        for arg in node.args:
            confidence = self._sql_taint_confidence(arg)
            if not confidence and isinstance(arg, ast.Name) and arg.id in self._tainted_sql_vars:
                confidence = "high"
            if confidence:
                self.findings.append(
                    _make_finding(
                        self.filename,
                        node,
                        "sql_injection",
                        confidence,
                        self._snippet(node.lineno),
                    )
                )
                break  # one finding per call site is enough

        for kw in node.keywords:
            confidence = self._sql_taint_confidence(kw.value)
            if not confidence and isinstance(kw.value, ast.Name) and kw.value.id in self._tainted_sql_vars:
                confidence = "high"
            if confidence:
                self.findings.append(
                    _make_finding(
                        self.filename,
                        node,
                        "sql_injection",
                        confidence,
                        self._snippet(node.lineno),
                    )
                )
                break

    def _sql_taint_confidence(self, expr: ast.expr) -> str | None:
        # f-string
        if isinstance(expr, ast.JoinedStr):
            return "high"
        # string concatenation with +
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return "high" if self._has_literal_string(expr) else "medium"
        # % formatting
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            return "high" if self._has_literal_string(expr) else "medium"
        # .format() call
        if isinstance(expr, ast.Call):
            # direct: "string".format(...)
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                return "high" if _is_literal_string(expr.func.value) else "medium"
            # via variable: x.format(...) where x is a string variable
            func_name = _dotted_name(expr.func)
            if func_name and func_name.endswith(".format"):
                return "high" if self._has_literal_string(expr.func.value) else "medium"
        return None

    def _has_literal_string(self, node: ast.expr) -> bool:
        if _is_literal_string(node):
            return True
        if isinstance(node, ast.BinOp):
            return self._has_literal_string(node.left) or self._has_literal_string(node.right)
        if isinstance(node, ast.Call):
            return self._has_literal_string(node.func)
        if isinstance(node, ast.JoinedStr):
            return True
        return False

    def _check_dangerous_call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        if not name:
            return

        # builtin eval/exec
        if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_BUILTINS:
            self.findings.append(
                _make_finding(
                    self.filename,
                    node,
                    "dangerous_call",
                    "high",
                    self._snippet(node.lineno),
                )
            )
            return

        # os.system, pickle.loads
        if name in _DANGEROUS_DOTTED:
            self.findings.append(
                _make_finding(
                    self.filename,
                    node,
                    "dangerous_call",
                    "high",
                    self._snippet(node.lineno),
                )
            )
            return

        # subprocess.* with shell=True
        if name.startswith("subprocess.") or name in _SUBPROCESS_SHELL_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        _make_finding(
                            self.filename,
                            node,
                            "dangerous_call",
                            "high",
                            self._snippet(node.lineno),
                        )
                    )
                    return

    def _check_yaml_load(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        if not name:
            return
        # matches yaml.load or bare load (common from-import pattern)
        is_yaml_load = name == "yaml.load" or (name == "load" and isinstance(node.func, ast.Name))
        if not is_yaml_load:
            return

        has_safe_loader = False
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    if kw.value.attr == "SafeLoader":
                        has_safe_loader = True
                elif isinstance(kw.value, ast.Name):
                    if kw.value.id == "SafeLoader":
                        has_safe_loader = True

        if has_safe_loader:
            return

        confidence = "high"
        # if explicit non-SafeLoader given, still flag but could be medium
        for kw in node.keywords:
            if kw.arg == "Loader":
                confidence = "medium"
                break

        self.findings.append(
            _make_finding(
                self.filename,
                node,
                "insecure_deserialization",
                confidence,
                self._snippet(node.lineno),
            )
        )


def scan_source(code: str, filename: str = "input.py") -> list[dict]:
    """
    Parse Python source with ast and return a list of findings.
    Each finding is a dict with keys:
    file, line_number, column, snippet, pattern_type, confidence
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [
            {
                "file": filename,
                "line_number": int(exc.lineno or 1),
                "column": int(exc.offset or 0),
                "snippet": str(exc.msg or "invalid syntax").strip(),
                "pattern_type": "parse_error",
                "confidence": "high",
            }
        ]

    lines = code.splitlines()
    visitor = _VulnerabilityVisitor(filename=filename, source_lines=lines)
    visitor.visit(tree)
    visitor.findings.sort(key=lambda f: (f["line_number"], f["column"]))
    return visitor.findings
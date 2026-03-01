#!/usr/bin/env python3
"""Enforce local Python style policies for PixelProof.

Rules enforced:
- Every class/function/method must have a docstring.
- Every function/method must have at most 8 code lines.
- Underscore-prefixed top-level functions must not be called from module-level code.
- Helper calls inside a function must reference underscore functions defined above,
  and those helper definitions must follow the same call sequence.
"""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass


FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class Violation:
    """Represent one style-policy violation.

    Args:
        path: File path where violation occurred.
        line: 1-based line number.
        message: Human-readable violation description.
    """

    path: str
    line: int
    message: str


def _read_text(path):
    """Read UTF-8 file content.

    Args:
        path: File path.

    Returns:
        File content as text.
    """
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _skip_dirs():
    """Return directory names excluded from scanning.

    Returns:
        Set of directory names.
    """
    return {".git", ".venv", "__pycache__", "build", "pixelproof.egg-info"}


def _iter_python_files(root):
    """Yield python file paths under a root directory.

    Args:
        root: Workspace root path.

    Yields:
        Absolute path to each .py file.
    """
    for cur_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in _skip_dirs()]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(cur_root, name)


def _parse_tree(path, text):
    """Parse source text into AST.

    Args:
        path: File path for error context.
        text: Python source code.

    Returns:
        Parsed AST module node.
    """
    return ast.parse(text, filename=path)


def _is_def(node):
    """Check whether AST node is class/function definition.

    Args:
        node: AST node.

    Returns:
        True when node is a definition node.
    """
    return isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))


def _all_defs(tree):
    """Collect all class/function definitions from AST.

    Args:
        tree: AST module node.

    Returns:
        List of definition nodes.
    """
    return [node for node in ast.walk(tree) if _is_def(node)]


def _docstring_ok(node):
    """Check if definition node has a docstring.

    Args:
        node: Definition node.

    Returns:
        True when docstring exists.
    """
    return ast.get_docstring(node) is not None


def _docstring_violations(path, defs):
    """Build violations for missing docstrings.

    Args:
        path: File path.
        defs: Definition nodes.

    Returns:
        List of violations.
    """
    missing = [node for node in defs if not _docstring_ok(node)]
    return [
        Violation(path, node.lineno, f"Missing docstring on '{node.name}'")
        for node in missing
    ]


def _docstring_range(node):
    """Compute line range occupied by function docstring.

    Args:
        node: Function or method node.

    Returns:
        Tuple of (start, end) lines for docstring, or (0, -1).
    """
    first = node.body[0] if node.body else None
    value = getattr(first, "value", None)
    is_const = isinstance(value, ast.Constant) and isinstance(
        getattr(value, "value", None), str
    )
    is_legacy = type(value).__name__ == "Str"
    is_doc = isinstance(first, ast.Expr) and (is_const or is_legacy)
    return (first.lineno, first.end_lineno) if is_doc else (0, -1)


def _line_is_code(text):
    """Check whether one line counts as code.

    Args:
        text: Source line text.

    Returns:
        True when line is non-empty and not a comment.
    """
    stripped = text.strip()
    return bool(stripped) and not stripped.startswith("#")


def _count_code_lines(node, lines):
    """Count code lines for one function/method definition.

    Args:
        node: Function or method node.
        lines: Full source file splitlines list.

    Returns:
        Number of code lines in definition body.
    """
    ds_start, ds_end = _docstring_range(node)
    indexes = range(node.lineno + 1, node.end_lineno + 1)
    usable = [idx for idx in indexes if not (ds_start <= idx <= ds_end)]
    return sum(1 for idx in usable if _line_is_code(lines[idx - 1]))


def _func_defs(defs):
    """Filter function and async-function nodes.

    Args:
        defs: All definition nodes.

    Returns:
        Function-like definition list.
    """
    return [
        node
        for node in defs
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _length_violations(path, funcs, lines):
    """Build violations for function length rule.

    Args:
        path: File path.
        funcs: Function/method definition nodes.
        lines: Source lines.

    Returns:
        List of violations.
    """
    long_funcs = [(node, _count_code_lines(node, lines)) for node in funcs]
    failing = [(node, count) for node, count in long_funcs if count > 8]
    return [
        Violation(
            path, node.lineno, f"Function '{node.name}' has {count} code lines (max 8)"
        )
        for node, count in failing
    ]


def _name_of_call(node):
    """Extract called function name from call node.

    Args:
        node: AST call node.

    Returns:
        Called function name or None.
    """
    func = getattr(node, "func", None)
    return func.id if isinstance(func, ast.Name) else None


def _module_level_nodes(tree):
    """Collect executable module-level statements.

    Args:
        tree: AST module node.

    Returns:
        List of module-level statement nodes.
    """
    return [node for node in tree.body if not _is_def(node)]


def _calls_in_nodes(nodes):
    """Collect simple-name call usages from AST node list.

    Args:
        nodes: AST statement nodes.

    Returns:
        List of called function names.
    """
    calls = [
        sub for node in nodes for sub in ast.walk(node) if isinstance(sub, ast.Call)
    ]
    return [name for name in (_name_of_call(call) for call in calls) if name]


def _top_level_func_positions(tree):
    """Map top-level function name to definition line.

    Args:
        tree: AST module node.

    Returns:
        Dictionary mapping function name to line number.
    """
    top = [node for node in tree.body if isinstance(node, FUNC_TYPES)]
    return {node.name: node.lineno for node in top}


def _top_level_functions(tree):
    """Return top-level function definitions.

    Args:
        tree: AST module node.

    Returns:
        List of top-level function nodes.
    """
    return [node for node in tree.body if isinstance(node, FUNC_TYPES)]


def _underscore_top_call_violations(path, tree):
    """Build violations for underscore functions called at module-level.

    Args:
        path: File path.
        tree: AST module node.

    Returns:
        List of violations.
    """
    module_nodes = _module_level_nodes(tree)
    called = _calls_in_nodes(module_nodes)
    bad = [name for name in called if name.startswith("_")]
    return [
        Violation(path, 1, f"Top-level code calls private function '{name}'")
        for name in sorted(set(bad))
    ]


def _local_call_order(node, known):
    """Compute ordered local helper calls inside a function.

    Args:
        node: Function definition node.
        known: Set of top-level function names.

    Returns:
        Ordered unique local call names.
    """
    raw = [call for call in ast.walk(node) if isinstance(call, ast.Call)]
    calls = sorted(
        raw,
        key=lambda call: (getattr(call, "lineno", 0), getattr(call, "col_offset", 0)),
    )
    calls = [_name_of_call(call) for call in calls]
    names = [name for name in calls if name and name in known]
    return list(dict.fromkeys(names))


def _call_sequence_valid(order, positions):
    """Check helper definition order follows call order.

    Args:
        order: Ordered helper function names.
        positions: Function-name to line-number mapping.

    Returns:
        True when definition positions are non-decreasing.
    """
    lines = [positions[name] for name in order]
    return lines == sorted(lines)


def _bad_helper_names(order, positions, node_name):
    """Return helper names missing underscore prefix.

    Args:
        order: Ordered helper names.
        positions: Function-name to line-number mapping.
        node_name: Caller function name.

    Returns:
        List of bad helper names.
    """
    return [
        name
        for name in order
        if name.startswith("_") is False and name in positions and name != node_name
    ]


def _below_caller_helpers(order, positions, caller_line):
    """Return helper names defined below caller function.

    Args:
        order: Ordered helper names.
        positions: Function-name to line-number mapping.
        caller_line: Caller function line number.

    Returns:
        List of below-caller helper names.
    """
    return [
        name
        for name in order
        if name in positions and positions[name] > caller_line and name.startswith("_")
    ]


def _underscore_name_issues(path, line, node_name, names):
    """Build violations for non-underscore helper names.

    Args:
        path: File path.
        line: Caller line number.
        node_name: Caller function name.
        names: Helper names missing underscore prefix.

    Returns:
        List of violations.
    """
    return [
        Violation(
            path, line, f"Helper '{name}' in '{node_name}' must be underscore-prefixed"
        )
        for name in names
    ]


def _order_issue(path, line, node_name, order, positions):
    """Build optional violation for helper call-order mismatch.

    Args:
        path: File path.
        line: Caller line number.
        node_name: Caller function name.
        order: Ordered helper calls.
        positions: Function-name to line-number mapping.

    Returns:
        List with zero or one violation.
    """
    if _call_sequence_valid(order, positions):
        return []
    return [
        Violation(path, line, f"Helpers in '{node_name}' are not defined in call order")
    ]


def _below_issue(path, line, node_name, names):
    """Build violations for helpers defined below caller.

    Args:
        path: File path.
        line: Caller line number.
        node_name: Caller function name.
        names: Helper names defined below caller.

    Returns:
        List of violations.
    """
    return [
        Violation(
            path, line, f"Helper '{name}' in '{node_name}' must be defined above caller"
        )
        for name in names
    ]


def _node_helper_issues(path, node, positions):
    """Build helper-ordering issues for one top-level function.

    Args:
        path: File path.
        node: Top-level function node.
        positions: Function-name to line-number mapping.

    Returns:
        List of violations.
    """
    order = _local_call_order(node, set(positions))
    bad_names = _bad_helper_names(order, positions, node.name)
    below = _below_caller_helpers(order, positions, node.lineno)
    issues = _underscore_name_issues(path, node.lineno, node.name, bad_names)
    issues.extend(_order_issue(path, node.lineno, node.name, order, positions))
    issues.extend(_below_issue(path, node.lineno, node.name, below))
    return issues


def _helper_flow_violations(path, tree):
    """Build violations for helper naming and top-to-bottom flow.

    Args:
        path: File path.
        tree: AST module node.

    Returns:
        List of violations.
    """
    positions = _top_level_func_positions(tree)
    top_funcs = _top_level_functions(tree)
    return [
        issue
        for node in top_funcs
        for issue in _node_helper_issues(path, node, positions)
    ]


def _policy_issues(path, tree, defs, lines):
    """Collect all policy issues for one parsed module.

    Args:
        path: File path.
        tree: AST module node.
        defs: Definition nodes.
        lines: Source lines.

    Returns:
        List of violations.
    """
    issues = _docstring_violations(path, defs)
    funcs = _func_defs(defs)
    issues.extend(_length_violations(path, funcs, lines))
    issues.extend(_underscore_top_call_violations(path, tree))
    issues.extend(_helper_flow_violations(path, tree))
    return issues


def _format_violation(item):
    """Format one violation for terminal output.

    Args:
        item: Violation instance.

    Returns:
        Formatted text line.
    """
    return f"{item.path}:{item.line}: {item.message}"


def _target_paths(root):
    """Resolve scan targets from file or directory input.

    Args:
        root: Target file or directory path.

    Returns:
        List of python file paths.
    """
    if os.path.isfile(root):
        return [root] if root.endswith(".py") else []
    return list(_iter_python_files(root))


def _analyze_file(path):
    """Analyze one python file and return all violations.

    Args:
        path: Python file path.

    Returns:
        List of violations.
    """
    text = _read_text(path)
    tree = _parse_tree(path, text)
    defs = _all_defs(tree)
    lines = text.splitlines()
    return _policy_issues(path, tree, defs, lines)


def _scan_target(root):
    """Scan one root target and collect all violations.

    Args:
        root: Target file or directory path.

    Returns:
        List of violations.
    """
    paths = _target_paths(root)
    grouped = [_analyze_file(path) for path in paths]
    return [issue for issues in grouped for issue in issues]


def _print_violations(violations):
    """Print sorted violations to stdout.

    Args:
        violations: Violation list.
    """
    for item in sorted(violations, key=lambda x: (x.path, x.line, x.message)):
        print(_format_violation(item))


def _exit_code(violations):
    """Compute process exit code from violations.

    Args:
        violations: Violation list.

    Returns:
        0 when clean else 1.
    """
    return 1 if violations else 0


def style_guard_main(argv=None):
    """Run style-guard checks over the workspace.

    Args:
        argv: Optional CLI arguments list.

    Returns:
        Process exit code.
    """
    args = argv if argv is not None else sys.argv[1:]
    root = os.path.abspath(args[0]) if args else os.getcwd()
    violations = _scan_target(root)
    _print_violations(violations)
    print(f"Checked style policies on {root} | violations={len(violations)}")
    return _exit_code(violations)


if __name__ == "__main__":
    raise SystemExit(style_guard_main())

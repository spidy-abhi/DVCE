import ast
import importlib.metadata
import json
import os
import re
from collections import deque
from pathlib import Path


SKIPPED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
MAX_GRAPH_NODES = 18
MAX_AFFECTED_NODES = 10
GRAPH_DEPTH = 1


def is_call_graph_request(question: str) -> bool:
    return bool(
        re.search(
            r"\bcall[\s-]*graph\b|\bfunction[\s-]+(?:call[\s-]+)?graph\b|"
            r"\bshow\s+(?:me\s+)?(?:the\s+)?(?:function\s+)?calls\b",
            question,
            re.IGNORECASE,
        )
    )


def _module_name(repository: Path, source_file: Path) -> str:
    parts = list(source_file.relative_to(repository).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or source_file.stem


def _distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _package_modules(package: str) -> set[str]:
    normalized_package = _distribution_name(package)
    modules = {
        module.lower()
        for module, distributions in importlib.metadata.packages_distributions().items()
        if any(_distribution_name(distribution) == normalized_package for distribution in distributions)
    }
    fallback = package.lower().replace("-", "_").replace(".", "_")
    modules.add(fallback.split("_")[0])
    modules.add(fallback)
    return modules


def _record_imports(nodes: list[ast.stmt], imports: dict[str, str]) -> None:
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".")[0]
                imports[bound_name] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"


def _scope_nodes(node: ast.AST):
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield current
        stack.extend(ast.iter_child_nodes(current))


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, module: str, source_file: str):
        self.module = module
        self.source_file = source_file
        self.scope: list[str] = []
        self.classes: list[str] = []
        self.functions: dict[str, dict] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()
        self.scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified_name = ".".join([self.module, *self.scope, node.name])
        self.functions[qualified_name] = {
            "node": node,
            "file": self.source_file,
            "line": node.lineno,
            "class": ".".join(self.classes),
            "module": self.module,
        }
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)


def _expression_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_path(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _package_imports_used(info: dict, module_imports: dict[str, str], package_modules: set[str]) -> bool:
    function_node = info["node"]
    used_names = {
        node.id for node in _scope_nodes(function_node) if isinstance(node, ast.Name)
    }
    imports = dict(module_imports)
    local_import_nodes = [
        node for node in _scope_nodes(function_node) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    _record_imports(local_import_nodes, imports)
    for bound_name, imported_path in imports.items():
        if bound_name not in used_names:
            continue
        root = imported_path.split(".", 1)[0].lower()
        if root in package_modules:
            return True
    return False


def _resolve_call(
    call_path: str,
    caller: dict,
    module_imports: dict[str, str],
    functions: dict[str, dict],
    names_by_module: dict[str, list[str]],
) -> str | None:
    parts = call_path.split(".")
    candidates = []
    if parts[0] in module_imports:
        candidates.append(".".join([module_imports[parts[0]], *parts[1:]]))
        candidates.append(module_imports[parts[0]])
    if len(parts) == 1 and parts[0] in module_imports:
        candidates.append(module_imports[parts[0]])
    if parts[0] in {"self", "cls"} and caller["class"]:
        candidates.append(".".join([caller["module"], caller["class"], *parts[1:]]))
    candidates.append(".".join([caller["module"], *parts]))
    for candidate in candidates:
        if candidate in functions:
            return candidate
    if len(parts) == 1:
        same_module_matches = [
            name
            for name in names_by_module.get(caller["module"], [])
            if name.rsplit(".", 1)[-1] == parts[0]
        ]
        if len(same_module_matches) == 1:
            return same_module_matches[0]
    return None


def _dot_quote(value: str) -> str:
    return json.dumps(value)


def build_package_call_graph(repository: Path, package: str) -> dict:
    repository = repository.resolve()
    modules: dict[str, dict] = {}
    functions: dict[str, dict] = {}

    for root, directories, filenames in os.walk(repository, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.lower() not in SKIPPED_DIRECTORIES
        )
        for filename in sorted(filenames):
            if not filename.lower().endswith(".py"):
                continue
            source_file = Path(root) / filename
            if source_file.is_symlink():
                continue
            try:
                source = source_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(source_file))
            except (OSError, UnicodeError, SyntaxError):
                continue

            module = _module_name(repository, source_file)
            relative_file = source_file.relative_to(repository).as_posix()
            module_imports: dict[str, str] = {}
            _record_imports(tree.body, module_imports)
            modules[module] = {"imports": module_imports}
            collector = _FunctionCollector(module, relative_file)
            collector.visit(tree)
            functions.update(collector.functions)

    names_by_module: dict[str, list[str]] = {}
    for qualified_name, info in functions.items():
        names_by_module.setdefault(info["module"], []).append(qualified_name)

    package_modules = _package_modules(package)
    affected_functions = {
        name
        for name, info in functions.items()
        if _package_imports_used(info, modules[info["module"]]["imports"], package_modules)
    }
    if not affected_functions:
        return {
            "dot": "",
            "affected_count": 0,
            "message": f"No functions directly using the {package} package were identified.",
        }

    edges: set[tuple[str, str]] = set()
    for caller_name, info in functions.items():
        for node in _scope_nodes(info["node"]):
            if not isinstance(node, ast.Call):
                continue
            call_path = _expression_path(node.func)
            if not call_path:
                continue
            callee_name = _resolve_call(
                call_path,
                info,
                modules[info["module"]]["imports"],
                functions,
                names_by_module,
            )
            if callee_name:
                edges.add((caller_name, callee_name))

    adjacent: dict[str, set[str]] = {name: set() for name in functions}
    for caller, callee in edges:
        adjacent[caller].add(callee)
        adjacent[callee].add(caller)

    affected_seeds = sorted(affected_functions)[:MAX_AFFECTED_NODES]
    selected = set(affected_seeds)
    queue = deque((name, 0) for name in affected_seeds)
    while queue and len(selected) < MAX_GRAPH_NODES:
        current, depth = queue.popleft()
        if depth >= GRAPH_DEPTH:
            continue
        for neighbor in sorted(adjacent[current]):
            if neighbor in selected:
                continue
            selected.add(neighbor)
            queue.append((neighbor, depth + 1))
            if len(selected) >= MAX_GRAPH_NODES:
                break

    lines = [
        "digraph call_graph {",
        '  graph [rankdir="TB", bgcolor="transparent", pad="0.15", nodesep="0.25", ranksep="0.35"];',
        '  node [shape="box", style="rounded,filled", fontname="Segoe UI", color="#64748b"];',
        '  edge [color="#64748b", arrowsize="0.7"];',
    ]
    for name in sorted(selected):
        info = functions[name]
        label = f"{name.rsplit('.', 1)[-1]}()\\n{Path(info['file']).name}:{info['line']}"
        color = "#fecaca" if name in affected_functions else "#dbeafe"
        lines.append(
            f"  {_dot_quote(name)} [label={_dot_quote(label)}, fillcolor={_dot_quote(color)}];"
        )
    for caller, callee in sorted(edges):
        if caller in selected and callee in selected:
            lines.append(f"  {_dot_quote(caller)} -> {_dot_quote(callee)};")
    lines.append("}")
    return {
        "dot": "\n".join(lines),
        "affected_count": len(affected_functions),
        "node_count": len(selected),
        "truncated": len(affected_functions) > len(affected_seeds) or len(selected) >= MAX_GRAPH_NODES,
        "message": "",
    }
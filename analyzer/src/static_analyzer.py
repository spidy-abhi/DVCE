import argparse
import ast
import json
import os
from collections import deque
from dataclasses import dataclass, field
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
HTTP_DECORATORS = {
    "delete": "DELETE",
    "get": "GET",
    "head": "HEAD",
    "options": "OPTIONS",
    "patch": "PATCH",
    "post": "POST",
    "put": "PUT",
}


@dataclass
class FunctionInfo:
    identifier: str
    name: str
    module: str
    class_name: str
    file: str
    line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef
    imports: dict[str, str] = field(default_factory=dict)
    routes: list[dict[str, str]] = field(default_factory=list)


def _module_name(repository: Path, source_file: Path) -> str:
    parts = list(source_file.relative_to(repository).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or source_file.stem


def _expression_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_path(node.value)
        return f"{parent}.{node.attr}" if parent else None
    if isinstance(node, ast.Call):
        return _expression_path(node.func)
    return None


def _nodes_in_scope(node: ast.AST):
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield current
        stack.extend(ast.iter_child_nodes(current))


def _imports_in_scope(nodes) -> dict[str, str]:
    imports = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".")[0]
                imports[bound_name] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return imports


def _route_entries(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, str]]:
    entries = []
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        target = call.func if call else decorator
        if isinstance(target, ast.Attribute):
            decorator_name = target.attr.lower()
        elif isinstance(target, ast.Name):
            decorator_name = target.id.lower()
        else:
            continue

        if decorator_name not in HTTP_DECORATORS and decorator_name not in {"route", "api_route"}:
            continue
        route = next(
            (argument.value for argument in call.args if isinstance(argument, ast.Constant) and isinstance(argument.value, str)),
            None,
        ) if call else None
        if route is None:
            continue

        methods = [HTTP_DECORATORS[decorator_name]] if decorator_name in HTTP_DECORATORS else ["GET"]
        if call and decorator_name in {"route", "api_route"}:
            methods_argument = next(
                (keyword.value for keyword in call.keywords if keyword.arg == "methods"),
                None,
            )
            if isinstance(methods_argument, (ast.List, ast.Tuple, ast.Set)):
                methods = [
                    item.value.upper()
                    for item in methods_argument.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ] or methods
        for method in methods:
            entries.append({"method": method, "route": route})
    return entries


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, module: str, source_file: str, module_imports: dict[str, str]):
        self.module = module
        self.source_file = source_file
        self.module_imports = module_imports
        self.scope: list[str] = []
        self.class_scope: list[str] = []
        self.functions: list[FunctionInfo] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.class_scope.append(node.name)
        self.generic_visit(node)
        self.class_scope.pop()
        self.scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        identifier = ".".join([self.module, *self.scope, node.name])
        local_imports = _imports_in_scope(_nodes_in_scope(node))
        imports = {**self.module_imports, **local_imports}
        self.functions.append(
            FunctionInfo(
                identifier=identifier,
                name=node.name,
                module=self.module,
                class_name=".".join(self.class_scope),
                file=self.source_file,
                line=node.lineno,
                node=node,
                imports=imports,
                routes=_route_entries(node),
            )
        )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)


def _resolve_call(
    call_path: str,
    function: FunctionInfo,
    functions: dict[str, FunctionInfo],
    functions_by_module: dict[str, list[str]],
) -> tuple[str, bool]:
    parts = call_path.split(".")
    candidates = []
    if parts[0] in {"self", "cls"} and function.class_name:
        candidates.append(".".join([function.module, function.class_name, *parts[1:]]))
    if parts[0] in function.imports:
        imported_path = function.imports[parts[0]]
        candidates.append(".".join([imported_path, *parts[1:]]))
        if len(parts) == 1:
            candidates.append(imported_path)
    candidates.append(".".join([function.module, *parts]))

    for candidate in candidates:
        if candidate in functions:
            return candidate, True
    if len(parts) == 1:
        same_module = [
            identifier
            for identifier in functions_by_module.get(function.module, [])
            if functions[identifier].name == parts[0]
        ]
        if len(same_module) == 1:
            return same_module[0], True

    if parts[0] in function.imports:
        imported_path = function.imports[parts[0]]
        return ".".join([imported_path, *parts[1:]]), False
    return call_path, False


def _matches_target(candidate: str, target: str) -> bool:
    candidate = candidate.removesuffix("()").strip(".")
    target = target.removesuffix("()").strip(".")
    if candidate == target:
        return True
    if "." not in target:
        return candidate.rsplit(".", 1)[-1] == target
    return candidate.endswith(f".{target}")


def _shortest_path(
    starts: list[str], targets: set[str], adjacency: dict[str, set[str]]
) -> list[str]:
    queue = deque((start, [start]) for start in starts)
    visited = set(starts)
    while queue:
        current, path = queue.popleft()
        if any(_matches_target(current, target) for target in targets):
            return path
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, [*path, neighbor]))
    return []


def analyze_project(project_path: str | Path, vulnerable_function: str) -> dict:
    """Analyze Python source and return deterministic function reachability evidence."""
    repository = Path(project_path).expanduser().resolve()
    if not repository.is_dir():
        raise NotADirectoryError(f"Project directory does not exist: {repository}")
    if not vulnerable_function.strip():
        raise ValueError("vulnerable_function must be a non-empty function name")

    functions: dict[str, FunctionInfo] = {}
    parse_errors = []
    modules = []
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
            except (OSError, UnicodeError, SyntaxError) as error:
                parse_errors.append(
                    {
                        "file": source_file.relative_to(repository).as_posix(),
                        "error": str(error),
                    }
                )
                continue

            module = _module_name(repository, source_file)
            imports = _imports_in_scope(tree.body)
            collector = _FunctionCollector(
                module,
                source_file.relative_to(repository).as_posix(),
                imports,
            )
            collector.visit(tree)
            modules.append((module, tree, imports))
            functions.update({function.identifier: function for function in collector.functions})

    functions_by_module: dict[str, list[str]] = {}
    for identifier, function in functions.items():
        functions_by_module.setdefault(function.module, []).append(identifier)

    calls = []
    adjacency: dict[str, set[str]] = {identifier: set() for identifier in functions}
    for function in functions.values():
        for node in _nodes_in_scope(function.node):
            if not isinstance(node, ast.Call):
                continue
            call_path = _expression_path(node.func)
            if not call_path:
                continue
            callee, resolved = _resolve_call(call_path, function, functions, functions_by_module)
            adjacency[function.identifier].add(callee)
            calls.append(
                {
                    "caller": function.identifier,
                    "callee": callee,
                    "file": function.file,
                    "line": node.lineno,
                    "resolved": resolved,
                    "vulnerable_target": _matches_target(callee, vulnerable_function),
                }
            )

    entry_points = []
    for function in functions.values():
        for route in function.routes:
            entry_points.append(
                {
                    "function": function.identifier,
                    "trigger": f"{route['method']} {route['route']}",
                    "file": function.file,
                    "line": function.line,
                }
            )
    entry_points.sort(key=lambda entry: (entry["trigger"], entry["function"]))

    vulnerable_matches = []
    for identifier, function in functions.items():
        if _matches_target(identifier, vulnerable_function):
            vulnerable_matches.append(
                {
                    "kind": "definition",
                    "name": identifier,
                    "file": function.file,
                    "line": function.line,
                }
            )
    for call in calls:
        if call["vulnerable_target"]:
            vulnerable_matches.append(
                {
                    "kind": "call",
                    "name": call["callee"],
                    "caller": call["caller"],
                    "file": call["file"],
                    "line": call["line"],
                }
            )
    vulnerable_matches.sort(
        key=lambda match: (match["file"], match["line"], match["kind"], match["name"])
    )
    targets = {match["name"] for match in vulnerable_matches}
    starts = [entry["function"] for entry in entry_points]
    path = _shortest_path(starts, targets, adjacency)
    selected_entry = next(
        (entry for entry in entry_points if path and entry["function"] == path[0]),
        None,
    )

    functions_output = [
        {
            "id": function.identifier,
            "name": function.name,
            "file": function.file,
            "line": function.line,
        }
        for function in sorted(functions.values(), key=lambda item: item.identifier)
    ]
    calls.sort(key=lambda call: (call["file"], call["line"], call["caller"], call["callee"]))
    return {
        "project": repository.name,
        "functions": functions_output,
        "calls": calls,
        "entry_points": entry_points,
        "vulnerable_function": {
            "query": vulnerable_function,
            "matches": vulnerable_matches,
        },
        "reachability": {
            "reachable": bool(path),
            "entry_point": selected_entry["trigger"] if selected_entry else None,
            "call_path": path,
        },
        "parse_errors": parse_errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Python call-path analyzer")
    parser.add_argument("project", help="Path to a Python project")
    parser.add_argument(
        "--vulnerable-function",
        required=True,
        help="Function name or qualified name, for example ExampleLibrary.parse_request",
    )
    arguments = parser.parse_args()
    result = analyze_project(arguments.project, arguments.vulnerable_function)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
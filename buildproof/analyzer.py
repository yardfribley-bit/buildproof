from __future__ import annotations

import ast
import json
import re
import tomllib
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    AnalysisReport,
    BusinessDomain,
    ClientCall,
    Component,
    Endpoint,
    Evidence,
    WebSurface,
)

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
IGNORED_PARTS = {
    ".git",
    ".next",
    ".venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "vendor",
}
API_LITERAL = re.compile(r"[\"'`](/(?:api|ws)/[^\"'`\s]*)[\"'`]")
IMPORT_RE = re.compile(
    r"(?:from\s+|import\s*(?:[^\"']+?\s+from\s+)?)[\"']([^\"']+)[\"']"
)


def _files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in SOURCE_SUFFIXES
        and not any(part in IGNORED_PARTS for part in path.parts)
    ]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _evidence(path: Path, root: Path, line: int, excerpt: str = "") -> Evidence:
    return Evidence(_relative(path, root), line, excerpt.strip()[:240])


def _route_from_next_page(path: Path, app_root: Path) -> str:
    parts = list(path.relative_to(app_root).parts[:-1])
    visible = [part for part in parts if not (part.startswith("(") and part.endswith(")"))]
    route = "/" + "/".join(visible)
    route = re.sub(r"\[\[\.\.\.([^]]+)]]", r"*\1", route)
    route = re.sub(r"\[\.\.\.([^]]+)]", r"*\1", route)
    route = re.sub(r"\[([^]]+)]", r":\1", route)
    return route.rstrip("/") or "/"


def _normalize_template(value: str) -> str:
    value = value.split("?", 1)[0]
    value = re.sub(r"\$\{[^}]+}", ":param", value)
    value = re.sub(r"\{[^}]+}", ":param", value)
    value = re.sub(r"\[[^]]+]", ":param", value)
    value = re.sub(r"/+", "/", value)
    return value.rstrip("/") or "/"


def _template_matches(client: str, server: str) -> bool:
    left = _normalize_template(client).split("/")
    right = _normalize_template(server).split("/")
    if len(left) != len(right):
        return False
    return all(a == b or a.startswith(":") or b.startswith(":") for a, b in zip(left, right))


def _resolve_import(source: Path, spec: str, root: Path, candidates: set[Path]) -> Path | None:
    if spec.startswith("@/"):
        base = root / "web" / spec[2:]
    elif spec.startswith("."):
        base = source.parent / spec
    else:
        return None
    variants = [base]
    variants.extend(base.with_suffix(suffix) for suffix in (".ts", ".tsx", ".js", ".jsx"))
    variants.extend(base / f"index{suffix}" for suffix in (".ts", ".tsx", ".js", ".jsx"))
    return next((item.resolve() for item in variants if item.resolve() in candidates), None)


def _frontend(root: Path, files: list[Path]) -> list[WebSurface]:
    app_root = root / "web" / "app"
    if not app_root.exists():
        return []
    candidate_set = {path.resolve() for path in files if path.suffix in {".js", ".jsx", ".ts", ".tsx"}}
    imports: dict[Path, list[Path]] = defaultdict(list)
    direct_calls: dict[Path, list[ClientCall]] = defaultdict(list)
    for path in candidate_set:
        text = _read(path)
        lines = text.splitlines()
        for match in API_LITERAL.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            literal = match.group(1)
            transport = "websocket" if "wsUrl(" in lines[line - 1] or "WebSocket" in lines[line - 1] else "http"
            direct_calls[path].append(
                ClientCall(literal, transport, _evidence(path, root, line, lines[line - 1]))
            )
        for spec in IMPORT_RE.findall(text):
            resolved = _resolve_import(path, spec, root, candidate_set)
            if resolved:
                imports[path].append(resolved)

    surfaces: list[WebSurface] = []
    for page in sorted(app_root.rglob("page.tsx")):
        queue = deque([page.resolve()])
        seen: set[Path] = set()
        calls: dict[tuple[str, str], ClientCall] = {}
        while queue and len(seen) < 600:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            for call in direct_calls.get(current, []):
                calls[(call.path, call.transport)] = call
            queue.extend(imports.get(current, []))
        surfaces.append(
            WebSurface(
                route=_route_from_next_page(page, app_root),
                source=_evidence(page, root, 1),
                calls=sorted(calls.values(), key=lambda item: item.path),
            )
        )
    return surfaces


def _literal(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _router_mounts(root: Path) -> dict[str, tuple[str, str]]:
    main = root / "deeptutor" / "api" / "main.py"
    text = _read(main)
    mounts: dict[str, tuple[str, str]] = {}
    pattern = re.compile(
        r"app\.include_router\(\s*([\w_]+)\.router\s*,(.*?)\)", re.DOTALL
    )
    for match in pattern.finditer(text):
        body = match.group(2)
        prefix = re.search(r"prefix\s*=\s*[\"']([^\"']+)", body)
        dependencies = "admin" if "_admin" in body or "require_admin" in body else "authenticated"
        mounts[match.group(1)] = (prefix.group(1) if prefix else "", dependencies)
    mounts["auth"] = ("/api/v1/auth", "public")
    return mounts


def _backend(root: Path, files: list[Path]) -> list[Endpoint]:
    mounts = _router_mounts(root)
    endpoints: list[Endpoint] = []
    router_root = root / "deeptutor" / "api" / "routers"
    api_main = root / "deeptutor" / "api" / "main.py"
    for path in files:
        if path.suffix != ".py" or (router_root not in path.parents and path != api_main):
            continue
        text = _read(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        module = path.stem
        prefix, default_auth = mounts.get(
            module, ("", "public" if path == api_main else "authenticated")
        )
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                call = decorator if isinstance(decorator, ast.Call) else None
                if call is None:
                    continue
                attr = call.func
                if not isinstance(attr, ast.Attribute) or not isinstance(attr.value, ast.Name):
                    continue
                if attr.value.id not in {"router", "app"} or attr.attr not in {
                    "get", "post", "put", "patch", "delete", "websocket"
                }:
                    continue
                route = _literal(call.args[0]) if call.args else ""
                if route is None:
                    continue
                transport = "websocket" if attr.attr == "websocket" else "http"
                method = "WS" if transport == "websocket" else attr.attr.upper()
                auth = default_auth
                decorator_source = ast.get_source_segment(text, decorator) or ""
                if "require_admin" in decorator_source:
                    auth = "admin"
                endpoints.append(
                    Endpoint(
                        method,
                        _normalize_template(prefix + route),
                        node.name,
                        auth,
                        transport,
                        _evidence(path, root, node.lineno, lines[node.lineno - 1]),
                    )
                )
    return sorted(endpoints, key=lambda item: (item.path, item.method))


def _technologies(root: Path) -> list[str]:
    tech: list[str] = []
    package = root / "web" / "package.json"
    if package.exists():
        try:
            deps = json.loads(_read(package)).get("dependencies", {})
        except json.JSONDecodeError:
            deps = {}
        if "next" in deps:
            tech.append("Next.js")
        if "react" in deps:
            tech.append("React")
        tech.append("TypeScript")
    pyproject = _read(root / "pyproject.toml")
    requirements = "\n".join(_read(path) for path in root.glob("requirements*.txt"))
    combined = (pyproject + requirements).lower()
    if "fastapi" in combined or (root / "deeptutor" / "api").exists():
        tech.append("FastAPI")
    if any(root.rglob("*.py")):
        tech.append("Python")
    if "sqlite" in combined or any("sqlite" in path.name.lower() for path in root.rglob("*.py")):
        tech.append("SQLite")
    return list(dict.fromkeys(tech))


def _components(root: Path) -> list[Component]:
    found: dict[tuple[str, str], Component] = {}
    for path in root.rglob("package.json"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        try:
            package = json.loads(_read(path))
        except json.JSONDecodeError:
            continue
        lock_path = path.with_name("package-lock.json")
        try:
            lock = json.loads(_read(lock_path)) if lock_path.is_file() else {}
        except json.JSONDecodeError:
            lock = {}
        locked_packages = lock.get("packages", {})
        legacy_dependencies = lock.get("dependencies", {})
        for scope in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in package.get(scope, {}).items():
                if isinstance(version, str):
                    layer = "工程工具" if scope == "devDependencies" else "前端"
                    locked = locked_packages.get(f"node_modules/{name}", {}).get("version", "")
                    locked = locked or legacy_dependencies.get(name, {}).get("version", "")
                    evidence_path = lock_path if locked else path
                    item = Component(name, version, locked, "npm", layer, scope, _evidence(evidence_path, root, 1, f'"{name}": "{locked or version}"'))
                    found.setdefault(("npm", name.lower()), item)
    for path in root.rglob("pyproject.toml"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        try:
            project = tomllib.loads(_read(path)).get("project", {})
        except (tomllib.TOMLDecodeError, AttributeError):
            continue
        groups = [("dependencies", project.get("dependencies", []))]
        groups.extend((f"optional:{name}", values) for name, values in project.get("optional-dependencies", {}).items())
        for scope, values in groups:
            for value in values:
                match = re.match(r"\s*([A-Za-z0-9_.-]+(?:\[[^]]+])?)\s*(.*)", str(value))
                if match:
                    name, version = match.group(1), match.group(2).strip() or "unspecified"
                    layer = "工程工具" if scope.startswith("optional:") and any(word in scope for word in ("test", "dev", "lint")) else "后端"
                    item = Component(name, version, "", "PyPI", layer, scope, _evidence(path, root, 1, str(value)))
                    found.setdefault(("pypi", name.lower()), item)
    requirement = re.compile(r"^\s*([A-Za-z0-9_.-]+(?:\[[^]]+])?)\s*([^;\s#]*)")
    for path in root.rglob("requirements*.txt"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        for line_number, line in enumerate(_read(path).splitlines(), 1):
            if not line.strip() or line.lstrip().startswith(("#", "-")):
                continue
            match = requirement.match(line)
            if match:
                name, version = match.group(1), match.group(2) or "unspecified"
                locked = version.removeprefix("==") if version.startswith("==") else ""
                item = Component(name, version, locked, "PyPI", "后端", "requirements", _evidence(path, root, line_number, line))
                found.setdefault(("pypi", name.lower()), item)
    return sorted(found.values(), key=lambda item: (item.ecosystem, item.name.lower()))


def _entrypoints(root: Path) -> list[Evidence]:
    patterns = ("run_server.py", "main.py", "server.py", "manage.py", "package.json")
    found: list[Evidence] = []
    for name in patterns:
        for path in root.rglob(name):
            if any(part in IGNORED_PARTS for part in path.parts):
                continue
            found.append(_evidence(path, root, 1))
            if len(found) >= 12:
                return found
    return found


def _domain_name(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 3 and parts[:2] == ["api", "v1"]:
        return parts[2].replace("_", "-")
    return "platform"


def analyze_repository(repo_path: str | Path) -> AnalysisReport:
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository does not exist: {root}")
    files = _files(root)
    pages = _frontend(root, files)
    endpoints = _backend(root, files)
    components = _components(root)
    for page in pages:
        for call in page.calls:
            matches = [endpoint for endpoint in endpoints if _template_matches(call.path, endpoint.path)]
            if matches:
                page.endpoints.extend(matches)
            else:
                page.unresolved_calls.append(call)

    domains: dict[str, BusinessDomain] = {}
    for endpoint in endpoints:
        name = _domain_name(endpoint.path)
        domains.setdefault(name, BusinessDomain(name)).endpoints.append(
            f"{endpoint.method} {endpoint.path}"
        )
    for page in pages:
        names = {_domain_name(endpoint.path) for endpoint in page.endpoints}
        for name in names:
            domains.setdefault(name, BusinessDomain(name)).pages.append(page.route)

    warnings: list[str] = []
    unresolved = sum(len(page.unresolved_calls) for page in pages)
    if unresolved:
        warnings.append(
            f"{unresolved} client request(s) could not be matched to a backend route."
        )
    return AnalysisReport(
        project=root.name,
        root=str(root),
        technologies=_technologies(root),
        entrypoints=_entrypoints(root),
        pages=pages,
        endpoints=endpoints,
        domains=sorted(domains.values(), key=lambda item: (-len(item.endpoints), item.name)),
        components=components,
        stats={
            "source_files": len(files),
            "pages": len(pages),
            "http_endpoints": sum(item.transport == "http" for item in endpoints),
            "websockets": sum(item.transport == "websocket" for item in endpoints),
            "client_calls": sum(len(item.calls) for item in pages),
            "mapped_calls": sum(
                1
                for page in pages
                for call in page.calls
                if any(_template_matches(call.path, endpoint.path) for endpoint in endpoints)
            ),
            "unresolved_calls": unresolved,
            "business_domains": len(domains),
            "components": len(components),
        },
        warnings=warnings,
        generated_at=datetime.now(UTC).isoformat(),
    )

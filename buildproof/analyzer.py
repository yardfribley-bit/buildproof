from __future__ import annotations

import ast
import json
import os
import re
import tomllib
import urllib.request
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    AnalysisReport,
    BusinessDomain,
    ClientCall,
    Component,
    Endpoint,
    Evidence,
    Vulnerability,
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
        bases = [parent / spec[2:] for parent in source.parents if parent == root or root in parent.parents]
    elif spec.startswith("."):
        bases = [source.parent / spec]
    else:
        return None
    variants = []
    for base in bases:
        variants.append(base)
        variants.extend(base.with_suffix(suffix) for suffix in (".ts", ".tsx", ".js", ".jsx"))
        variants.extend(base / f"index{suffix}" for suffix in (".ts", ".tsx", ".js", ".jsx"))
    return next((item.resolve() for item in variants if item.resolve() in candidates), None)


def _frontend(root: Path, files: list[Path]) -> list[WebSurface]:
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
    page_files = [path for path in candidate_set if re.fullmatch(r"page\.(?:js|jsx|ts|tsx)", path.name)]
    for page in sorted(page_files):
        app_root = next((parent for parent in page.parents if parent.name == "app"), None)
        if app_root is None:
            continue
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
    mounts: dict[str, tuple[str, str]] = {}
    constants: dict[str, str] = {}
    python_files = [path for path in root.rglob("*.py") if not any(part in IGNORED_PARTS for part in path.parts)]
    for path in python_files:
        for name, value in re.findall(r"^\s*([A-Z][A-Z0-9_]*)[^=\n]*=\s*[\"']([^\"']+)", _read(path), re.MULTILINE):
            constants[name] = value
    root_prefixes: set[str] = set()
    pattern = re.compile(
        r"([\w_]+)\.include_router\(\s*([\w_.]+)\s*,(.*?)\)", re.DOTALL
    )
    for path in python_files:
        for match in pattern.finditer(_read(path)):
            receiver, expression, body = match.groups()
            prefix = re.search(r"prefix\s*=\s*[\"']([^\"']+)", body)
            prefix_value = prefix.group(1) if prefix else ""
            if not prefix_value:
                prefix_expression = re.search(r"prefix\s*=\s*([\w.]+)", body)
                if prefix_expression:
                    prefix_value = constants.get(prefix_expression.group(1).split(".")[-1], "")
            dependencies = "admin" if "_admin" in body or "require_admin" in body else "authenticated"
            if expression.endswith(".router"):
                module = expression.split(".")[-2]
            else:
                module = expression.split(".")[-1].removesuffix("_router")
            if module != "router":
                mounts[module] = (prefix_value, dependencies)
            if receiver == "app" and prefix_value:
                root_prefixes.add(prefix_value)
    if len(root_prefixes) == 1:
        root_prefix = next(iter(root_prefixes))
        mounts = {
            module: (prefix if prefix.startswith(root_prefix) else root_prefix + prefix, auth)
            for module, (prefix, auth) in mounts.items()
        }
    return mounts


def _backend(root: Path, files: list[Path]) -> list[Endpoint]:
    mounts = _router_mounts(root)
    endpoints: list[Endpoint] = []
    for path in files:
        if path.suffix != ".py":
            continue
        text = _read(path)
        if "@router." not in text and "@app." not in text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        module = path.stem
        prefix, default_auth = mounts.get(
            module, ("", "public" if path.name in {"main.py", "app.py"} else "authenticated")
        )
        router_declaration = re.search(r"router\s*=\s*APIRouter\((.*?)\)", text, re.DOTALL)
        if router_declaration:
            local_prefix = re.search(r"prefix\s*=\s*[\"']([^\"']+)", router_declaration.group(1))
            if local_prefix and not prefix.endswith(local_prefix.group(1)):
                prefix += local_prefix.group(1)
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
    workspace_locks: dict[str, tuple[str, Path]] = {}
    for lock_path in root.rglob("pnpm-lock.yaml"):
        if any(part in IGNORED_PARTS for part in lock_path.parts):
            continue
        section = ""
        versions: dict[str, set[str]] = defaultdict(set)
        for line in _read(lock_path).splitlines():
            if line and not line.startswith(" "):
                section = line.rstrip(":")
                continue
            if section not in {"packages", "snapshots"}:
                continue
            match = re.match(r"^\s{2}(.+):\s*$", line)
            if not match:
                continue
            key = match.group(1).strip().strip("'\"").lstrip("/")
            if key.startswith(("file:", "link:", "workspace:")) or "@" not in key:
                continue
            name, version = key.rsplit("@", 1)
            version = version.split("(", 1)[0]
            if name and re.match(r"^\d", version):
                versions[name].add(version)
        for name, candidates in versions.items():
            if len(candidates) == 1:
                workspace_locks[name] = (next(iter(candidates)), lock_path)
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
                    workspace_locked, workspace_path = workspace_locks.get(name, ("", path))
                    locked = locked or workspace_locked
                    evidence_path = lock_path if lock_path.is_file() and locked else workspace_path if workspace_locked else path
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


def _osv_json(url: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def _scan_vulnerabilities(components: list[Component]) -> list[Component]:
    if os.environ.get("BUILDPROOF_OSV", "").lower() not in {"1", "true", "yes"}:
        return components
    indexed = [(index, item) for index, item in enumerate(components) if item.locked_version]
    queries = [
        {"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.locked_version}
        for _, item in indexed
    ]
    try:
        batch = _osv_json("https://api.osv.dev/v1/querybatch", {"queries": queries}) if queries else {"results": []}
        results = batch.get("results", [])
        ids = sorted({vuln["id"] for result in results for vuln in result.get("vulns", []) if vuln.get("id")})
        with ThreadPoolExecutor(max_workers=8) as executor:
            details = dict(zip(ids, executor.map(lambda item: _osv_json(f"https://api.osv.dev/v1/vulns/{item}"), ids)))
    except (OSError, TimeoutError, json.JSONDecodeError):
        return [replace(item, scan_status="scan_error" if item.locked_version else "missing_version") for item in components]
    updated = list(components)
    for (index, item), result in zip(indexed, results):
        vulnerabilities = []
        for brief in result.get("vulns", []):
            detail = details.get(brief.get("id"), brief)
            vuln_id = str(detail.get("id", brief.get("id", "")))
            vulnerabilities.append(
                Vulnerability(
                    vuln_id,
                    [str(alias) for alias in detail.get("aliases", [])],
                    str(detail.get("summary", "Known vulnerability")),
                    f"https://osv.dev/vulnerability/{vuln_id}",
                )
            )
        updated[index] = replace(item, scan_status="scanned", vulnerabilities=vulnerabilities)
    for index, item in enumerate(updated):
        if not item.locked_version:
            updated[index] = replace(item, scan_status="missing_version")
    return updated


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
    components = _scan_vulnerabilities(_components(root))
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
            "scanned_components": sum(item.scan_status == "scanned" for item in components),
            "vulnerable_components": sum(bool(item.vulnerabilities) for item in components),
            "vulnerabilities": sum(len(item.vulnerabilities) for item in components),
        },
        warnings=warnings,
        generated_at=datetime.now(UTC).isoformat(),
    )

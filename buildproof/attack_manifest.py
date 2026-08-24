from __future__ import annotations

import ast
import re
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import CallRelation


SINK_PATTERNS = {
    "ssrf": re.compile(r"\b(?:requests|httpx|aiohttp)\s*\.\s*(?:get|post|put|patch|delete|request)\s*\("),
    "sql-injection": re.compile(r"\b(?:execute|executemany|raw|text)\s*\("),
    "command-injection": re.compile(r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output))\s*\("),
    "file-access": re.compile(r"\b(?:open|Path)\s*\(|\.(?:read_text|write_text|read_bytes|write_bytes)\s*\("),
    "xss": re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|mark_safe\s*\(|Markup\s*\("),
}

RISK_META = {
    "ssrf": (85, "外部输入可能到达服务端 HTTP 客户端", "服务端向隔离回连地址发出请求"),
    "sql-injection": (90, "请求处理路径包含原生 SQL 执行点", "安全测试字符串改变查询语义"),
    "command-injection": (95, "请求处理路径包含系统命令执行点", "隔离容器中执行无害标记命令"),
    "file-access": (80, "请求处理路径包含文件系统访问点", "越权读取或写入隔离测试文件"),
    "xss": (75, "前端路径包含未转义 HTML 渲染点", "无害测试标记在浏览器 DOM 中执行"),
}


def _function_source(path: Path, handler: str) -> tuple[str, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "", 1
    if path.suffix == ".py":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == handler:
                    lines = text.splitlines()
                    return "\n".join(lines[node.lineno - 1 : node.end_lineno]), node.lineno
        except SyntaxError:
            pass
    return text, 1


def _parameters(path: str) -> list[str]:
    return sorted(set(re.findall(r"(?::|\$\{|\{)([A-Za-z_][\w-]*)", path)))


def build_attack_manifest(
    root: Path,
    project: str,
    source: str,
    generated_at: str,
    relations: list[CallRelation],
) -> dict[str, Any]:
    surfaces: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    hypothesis_count = 0
    for index, relation in enumerate(relations, 1):
        endpoint = relation.backend or relation.api
        key = (
            relation.page,
            relation.call.method,
            relation.call.path,
            endpoint.method if endpoint else "",
            endpoint.path if endpoint else "",
        )
        if key in seen:
            continue
        seen.add(key)
        hypotheses: list[dict[str, Any]] = []
        signals: list[dict[str, Any]] = []
        if endpoint and endpoint.layer == "backend":
            source_path = root / endpoint.evidence.path
            body, start_line = _function_source(source_path, endpoint.handler)
            for risk_type, pattern in SINK_PATTERNS.items():
                match = pattern.search(body)
                if not match:
                    continue
                line = start_line + body.count("\n", 0, match.start())
                priority, reason, success = RISK_META[risk_type]
                signal = {
                    "type": risk_type,
                    "symbol": match.group(0).strip(),
                    "evidence": {"path": endpoint.evidence.path, "line": line},
                }
                signals.append(signal)
                hypotheses.append(
                    {
                        "type": risk_type,
                        "status": "candidate",
                        "priority": priority,
                        "reason": reason,
                        "success_condition": success,
                    }
                )
            params = _parameters(endpoint.path)
            if params and endpoint.auth != "public" and endpoint.method in {"GET", "PUT", "PATCH", "DELETE"}:
                hypotheses.append(
                    {
                        "type": "idor",
                        "status": "candidate",
                        "priority": 82,
                        "reason": "已认证接口使用客户端可控对象标识，需要验证对象级授权",
                        "success_condition": "身份 A 能读取或修改属于身份 B 的对象",
                    }
                )
            if endpoint.auth == "public" and endpoint.method in {"POST", "PUT", "PATCH", "DELETE"}:
                hypotheses.append(
                    {
                        "type": "broken-authentication",
                        "status": "candidate",
                        "priority": 88,
                        "reason": "可改变状态的接口未发现静态认证依赖",
                        "success_condition": "匿名身份成功执行受保护的状态变更",
                    }
                )
        hypothesis_count += len(hypotheses)
        surfaces.append(
            {
                "id": f"surface-{index}",
                "page": relation.page,
                "request": {"method": relation.call.method, "path": relation.call.path, "transport": relation.call.transport},
                "api": asdict(relation.api) if relation.api else None,
                "backend": asdict(relation.backend) if relation.backend else None,
                "relation_status": relation.status,
                "parameters": _parameters(relation.call.path),
                "sinks": signals,
                "hypotheses": hypotheses,
                "context": [asdict(item) for item in relation.evidence],
            }
        )
    return {
        "schema_version": "buildproof.attack-manifest.v1",
        "project": project,
        "source": source,
        "generated_at": generated_at,
        "safety": {"requires_authorization": True, "recommended_target": "isolated-staging"},
        "summary": {
            "attack_surfaces": len(surfaces),
            "candidate_hypotheses": hypothesis_count,
            "unresolved_surfaces": sum(item["relation_status"] == "unresolved" for item in surfaces),
        },
        "attack_surfaces": surfaces,
    }

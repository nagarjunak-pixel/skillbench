"""JSON-RPC 2.0 stdio MCP server exposing SkillBench static security verification."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from skillbench import __version__
from skillbench.engine.analyzer import audit_skill, run_kernel_benchmark
from skillbench.suite.external_bench import run_external_corpus_benchmark
from skillbench.suite.regression import run_behavioral_suite

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "audit_skill_artifact",
        "description": "Audit a SKILL.md instruction file and optional .mcp.json manifest using C++20 Aho-Corasick & taint reachability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_markdown": {"type": "string"},
                "mcp_json_text": {"type": "string"},
            },
            "required": ["skill_markdown"],
        },
    },
    {
        "name": "run_behavioral_suite",
        "description": "Execute the 30-case OWASP ASI & MCPSHIELD enterprise behavioral regression suite.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_external_benchmark",
        "description": "Run reproducible static benchmark on Trail of Bits overtly-malicious-skills + 24 real upstream community SKILL.md files.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "benchmark_kernel",
        "description": "Benchmark C++20 Aho-Corasick + Taint Prover against pure-Python fallback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "num_docs": {"type": "integer", "default": 1000},
            },
        },
    },
]


def handle_jsonrpc_message(req: dict[str, Any]) -> dict[str, Any] | None:
    method = str(req.get("method", ""))
    req_id = req.get("id")

    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "skillbench-mcp", "version": __version__},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        params = req.get("params", {})
        if not isinstance(params, dict):
            params = {}
        tname = str(params.get("name", ""))
        targs = params.get("arguments", {})
        if not isinstance(targs, dict):
            targs = {}

        if tname == "audit_skill_artifact":
            skill_md = str(targs.get("skill_markdown", ""))
            mcp_txt = targs.get("mcp_json_text")
            rep = audit_skill(skill_md, str(mcp_txt) if mcp_txt is not None else None)
            payload = rep.model_dump_json()
        elif tname == "run_behavioral_suite":
            payload = run_behavioral_suite().model_dump_json()
        elif tname == "run_external_benchmark":
            payload = run_external_corpus_benchmark().model_dump_json()
        elif tname == "benchmark_kernel":
            ndocs = int(targs.get("num_docs", 1000))
            payload = run_kernel_benchmark(num_docs=max(10, ndocs), iterations=2).model_dump_json()
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Unknown tool: {tname}"},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": payload}]},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def run_stdio_server(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            out_stream.write(json.dumps(err) + "\n")
            out_stream.flush()
            continue

        resp = handle_jsonrpc_message(msg)
        if resp is not None:
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()

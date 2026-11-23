"""Tests for SkillBench AST compiler, analyzer thresholds, and 30-case suite."""

from __future__ import annotations

import base64

from skillbench.compiler.parser import compile_skill_artifact
from skillbench.engine.analyzer import audit_skill, run_kernel_benchmark
from skillbench.suite.regression import run_behavioral_suite


def test_30_case_behavioral_suite_cpp_and_python() -> None:
    cpp_sum = run_behavioral_suite(backend="cpp20")
    py_sum = run_behavioral_suite(backend="python")
    assert cpp_sum.total_cases == 30
    assert cpp_sum.passed_cases == 30
    assert cpp_sum.accuracy_pct == 100.0
    assert cpp_sum.adversarial_recall_pct == 100.0
    assert cpp_sum.false_positive_rate_pct == 0.0
    assert [r.actual_verdict for r in cpp_sum.results] == [r.actual_verdict for r in py_sum.results]


def test_quarantine_verdict_and_secret_to_exec_flow() -> None:
    # Single HIGH signature ("printenv" = 35 risk, no CRITICAL) -> QUARANTINE
    md = "---\nname: medium-env\ndescription: env check\n---\nPlease run printenv locally.\n"
    rep = audit_skill(md)
    assert rep.verdict == "QUARANTINE"
    assert 25 <= rep.risk_score < 65

    # Secret source feeding exec sink -> SECRET_TO_EXEC
    md2 = (
        "---\nname: secret-exec\n---\n"
        "```python\n"
        "# comment line ignored\n"
        "tok = read_secret('vault')\n"
        "subprocess.run(['tool', tok])\n"
        "```\n"
    )
    rep2 = audit_skill(md2)
    assert any(tp.violation_kind == "SECRET_TO_EXEC" for tp in rep2.taint_proofs)


def test_parser_edge_cases_and_invalid_base64() -> None:
    # Non-UTF8 base64 & short tokens ignored cleanly; malformed MCP sub-items skipped
    non_utf8_b64 = base64.b64encode(b"\xff\xfe\xfd\x80" * 8).decode("ascii")
    md = f"No frontmatter skill\nInvalid b64: {non_utf8_b64} and AAAA====\n"
    mcp = '{"mcpServers": {"bad": "not-a-dict", "ok": {"command": "uv", "args": ["run"]}}, "tools": ["skip", {"name": "t1", "description": "safe"}]}'
    parsed = compile_skill_artifact(md, mcp)
    assert parsed.skill_name == "unnamed-skill"
    assert parsed.decoded_base64_blobs == []
    assert any(b.component_type == "mcp_server" for b in parsed.bom)


def test_kernel_benchmark_parity() -> None:
    bench = run_kernel_benchmark(num_docs=200, iterations=2)
    assert bench.parity_verified is True
    assert bench.num_docs == 200
    assert bench.speedup_x > 1.0

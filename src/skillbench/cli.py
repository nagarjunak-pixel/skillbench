"""Typer CLI entrypoint for SkillBench."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
import uvicorn
from rich.console import Console

from skillbench.engine.analyzer import audit_skill, run_kernel_benchmark
from skillbench.mcp.server import run_stdio_server
from skillbench.suite.regression import run_behavioral_suite

app = typer.Typer(
    name="skillbench",
    help="Enterprise SKILL.md & MCP Static Taint Analyzer & C++20 Aho-Corasick Prover",
    no_args_is_help=True,
)
console = Console()


@app.command("audit")
def cmd_audit(
    skill_path: Path = typer.Argument(..., exists=True, readable=True, help="Path to SKILL.md"),
    mcp_path: Path | None = typer.Option(None, "--mcp", help="Optional .mcp.json path"),
    backend: Literal["cpp20", "python"] = typer.Option("cpp20", "--backend"),
    fail_on_block: bool = typer.Option(False, "--fail-on-block"),
) -> None:
    """Audit a SKILL.md file and optional .mcp.json manifest."""
    skill_md = skill_path.read_text(encoding="utf-8")
    mcp_txt = mcp_path.read_text(encoding="utf-8") if mcp_path is not None else None
    report = audit_skill(skill_md, mcp_txt, backend=backend)
    console.print_json(report.model_dump_json(indent=2))
    if fail_on_block and report.verdict != "PASS":
        raise typer.Exit(code=2)


@app.command("suite")
def cmd_suite(
    backend: Literal["cpp20", "python"] = typer.Option("cpp20", "--backend"),
) -> None:
    """Run the 30-case OWASP ASI & MCPSHIELD behavioral regression suite."""
    summary = run_behavioral_suite(backend=backend)
    console.print_json(summary.model_dump_json(indent=2))
    if summary.passed_cases != summary.total_cases:  # pragma: no cover
        raise typer.Exit(code=1)


@app.command("bench")
def cmd_bench(
    num_docs: int = typer.Option(5000, "--docs", min=10, max=50000),
    iterations: int = typer.Option(5, "--iterations", min=1, max=25),
) -> None:
    """Benchmark C++20 Aho-Corasick + Taint Prover vs pure-Python fallback."""
    rep = run_kernel_benchmark(num_docs=num_docs, iterations=iterations)
    console.print_json(rep.model_dump_json(indent=2))


@app.command("mcp")
def cmd_mcp() -> None:
    """Start JSON-RPC 2.0 MCP server over stdio."""
    run_stdio_server()


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8170, "--port"),
) -> None:  # pragma: no cover
    """Start FastAPI REST server on :8170."""
    uvicorn.run("skillbench.api.app:app", host=host, port=port, log_level="info")


if __name__ == "__main__":  # pragma: no cover
    app()

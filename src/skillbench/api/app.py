"""FastAPI REST API exposing SkillBench static taint & external benchmark suite (:8170)."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from skillbench import __version__
from skillbench.engine.analyzer import THREAT_SIGNATURES, audit_skill, run_kernel_benchmark
from skillbench.models import (
    BenchmarkReport,
    ExternalBenchmarkReport,
    SkillAuditReport,
    SkillBomComponent,
    SuiteSummary,
)
from skillbench.suite.external_bench import run_external_corpus_benchmark
from skillbench.suite.regression import SUITE_CASES, run_behavioral_suite

app = FastAPI(
    title="SkillBench Enterprise Agent-Skill & MCP Taint Prover API",
    version=__version__,
    description="C++20 Aho-Corasick Injection/Exfiltration Scanner, Multi-File Bundle De-Obfuscator & Directed Taint Prover",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_COUNTERS: dict[str, int] = {
    "audits_total": 0,
    "blocked_total": 0,
    "suite_runs_total": 0,
    "external_bench_runs_total": 0,
}


class AuditRequest(BaseModel):
    skill_markdown: str = Field(min_length=1)
    mcp_json_text: str | None = None
    backend: Literal["cpp20", "python"] = "cpp20"


class BenchRequest(BaseModel):
    num_docs: int = Field(default=2000, ge=10, le=50000)
    iterations: int = Field(default=3, ge=1, le=20)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "skillbench",
        "version": __version__,
        "port": 8170,
        "signatures": len(THREAT_SIGNATURES),
        "suite_cases": len(SUITE_CASES),
    }


@app.get("/metrics")
def metrics() -> dict[str, int]:
    return dict(_COUNTERS)


@app.post("/v1/audit", response_model=SkillAuditReport)
def post_audit(req: AuditRequest) -> SkillAuditReport:
    report = audit_skill(req.skill_markdown, req.mcp_json_text, backend=req.backend)
    _COUNTERS["audits_total"] += 1
    if report.verdict != "PASS":
        _COUNTERS["blocked_total"] += 1
    return report


@app.post("/v1/bom", response_model=list[SkillBomComponent])
def post_bom(req: AuditRequest) -> list[SkillBomComponent]:
    report = audit_skill(req.skill_markdown, req.mcp_json_text, backend=req.backend)
    return report.bom


@app.post("/v1/suite/run", response_model=SuiteSummary)
def post_suite(backend: Literal["cpp20", "python"] = "cpp20") -> SuiteSummary:
    _COUNTERS["suite_runs_total"] += 1
    return run_behavioral_suite(backend=backend)


@app.post("/v1/external-bench", response_model=ExternalBenchmarkReport)
def post_external_bench(backend: Literal["cpp20", "python"] = "cpp20") -> ExternalBenchmarkReport:
    _COUNTERS["external_bench_runs_total"] += 1
    return run_external_corpus_benchmark(backend=backend)


@app.post("/v1/bench", response_model=BenchmarkReport)
def post_bench(req: BenchRequest) -> BenchmarkReport:
    return run_kernel_benchmark(num_docs=req.num_docs, iterations=req.iterations)

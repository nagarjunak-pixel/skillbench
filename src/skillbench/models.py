"""Strict Pydantic v2 data contracts for SkillBench."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

VerdictLiteral = Literal["PASS", "QUARANTINE", "BLOCK"]
SeverityLiteral = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LayerLiteral = Literal[
    "raw_markdown",
    "html_comment",
    "decoded_base64",
    "unicode_bidi",
    "mcp_schema",
    "companion_script",
    "archive_container",
    "bytecode_artifact",
]
ComponentTypeLiteral = Literal[
    "skill",
    "mcp_server",
    "mcp_tool",
    "code_block",
    "companion_script",
    "archive_container",
    "bytecode_artifact",
]


class SkillNode(BaseModel):
    node_id: int
    name: str
    kind: Literal[
        "source_untrusted", "source_secret", "transform", "sanitizer", "sink_net", "sink_exec"
    ]
    role_mask: int
    risk_weight: int = Field(ge=0, le=100)
    evidence: str


class SkillEdge(BaseModel):
    src: int
    dst: int
    reason: str


class ThreatFinding(BaseModel):
    rule_id: str
    owasp_asi: str
    severity: SeverityLiteral
    layer: LayerLiteral
    matched_signature: str
    description: str


class TaintProof(BaseModel):
    violation_kind: Literal[
        "UNTRUSTED_TO_EXEC",
        "UNTRUSTED_TO_NET",
        "SECRET_TO_NET",
        "SECRET_TO_EXEC",
    ]
    owasp_asi: str
    source_node: str
    sink_node: str
    hops: int
    risk_score: int
    severity: SeverityLiteral


class SkillBomComponent(BaseModel):
    component_type: ComponentTypeLiteral
    name: str
    sha256: str
    capabilities: list[str]


class SkillAuditReport(BaseModel):
    skill_name: str
    artifact_sha256: str
    verdict: VerdictLiteral
    risk_score: int = Field(ge=0, le=100)
    kernel_backend: Literal["cpp20", "python"]
    scan_latency_ms: float
    bidi_trojan_count: int
    hidden_comment_blocks: int
    decoded_base64_blobs: int
    findings: list[ThreatFinding]
    taint_proofs: list[TaintProof]
    nodes: list[SkillNode]
    edges: list[SkillEdge]
    bom: list[SkillBomComponent]


class SuiteCaseResult(BaseModel):
    case_id: str
    title: str
    category: Literal["benign", "adversarial"]
    expected_blocked: bool
    actual_verdict: VerdictLiteral
    passed: bool
    risk_score: int
    finding_count: int
    taint_count: int


class SuiteSummary(BaseModel):
    total_cases: int
    passed_cases: int
    accuracy_pct: float
    adversarial_recall_pct: float
    false_positive_rate_pct: float
    total_latency_ms: float
    results: list[SuiteCaseResult]


class BenchmarkReport(BaseModel):
    num_docs: int
    num_patterns: int
    graph_nodes: int
    graph_edges: int
    cpp20_total_ms: float
    python_total_ms: float
    speedup_x: float
    parity_verified: bool


class ExternalCaseResult(BaseModel):
    case_id: str
    corpus_group: Literal[
        "trailofbits_overtly_malicious",
        "pure_prose_social_engineering_boundary",
        "benign_community_upstream",
    ]
    source_repo: str
    commit_sha: str
    skill_path: str
    attack_vector: str
    v1_0_skill_md_only_verdict: VerdictLiteral
    v1_1_bundle_verdict: VerdictLiteral
    risk_score: int
    scan_latency_ms: float
    matched_rules: list[str]
    sha256_verified: bool


class ExternalBenchmarkReport(BaseModel):
    schema_version: str
    backend: Literal["cpp20", "python"]
    total_cases: int
    tob_malicious_total: int
    tob_v1_0_skill_md_only_intercepted: int
    tob_v1_1_hard_blocked: int
    tob_v1_1_quarantined: int
    tob_v1_1_gate_intercept_recall_pct: float
    tob_v1_1_strict_block_recall_pct: float
    prose_social_engineering_total: int
    prose_social_engineering_intercepted: int
    prose_social_engineering_recall_pct: float
    benign_upstream_total: int
    benign_v1_0_false_positives: int
    benign_v1_0_fpr_pct: float
    benign_v1_1_false_positives: int
    benign_v1_1_fpr_pct: float
    total_scan_latency_ms: float
    mean_scan_latency_ms: float
    handoff_boundary_note: str
    results: list[ExternalCaseResult]

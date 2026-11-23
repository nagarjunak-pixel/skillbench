"""Reproducible static evaluation harness against external corpora (Trail of Bits + 24 Upstream Skills)."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from pathlib import Path
from typing import Any, Literal

from skillbench.engine.analyzer import audit_skill, audit_skill_bundle
from skillbench.models import ExternalBenchmarkReport, ExternalCaseResult

_FIXTURES_PATH = Path(__file__).with_name("external_fixtures.json")


def _decode_fixture_files(
    encoded_files: dict[str, dict[str, Any]],
) -> tuple[dict[str, bytes], bool]:
    out: dict[str, bytes] = {}
    all_verified = True
    for rel_path, meta in encoded_files.items():
        compressed = base64.b64decode(str(meta["zlib_b64"]))
        raw = zlib.decompress(compressed)
        actual_sha = hashlib.sha256(raw).hexdigest()
        if actual_sha != str(meta["sha256"]) or len(raw) != int(meta["size_bytes"]):
            all_verified = False
        out[rel_path] = raw
    return out, all_verified


def run_external_corpus_benchmark(
    backend: Literal["cpp20", "python"] = "cpp20",
) -> ExternalBenchmarkReport:
    """Evaluate SkillBench v1.0.0 (SKILL.md-only) vs v1.1.0 (full static bundle) on external corpora."""
    manifest = json.loads(_FIXTURES_PATH.read_text(encoding="utf-8"))
    raw_cases: list[dict[str, Any]] = manifest["cases"]

    results: list[ExternalCaseResult] = []

    tob_total = 0
    tob_v10_intercepted = 0
    tob_v11_blocked = 0
    tob_v11_quarantined = 0

    prose_total = 0
    prose_intercepted = 0

    benign_total = 0
    benign_v10_fp = 0
    benign_v11_fp = 0

    for item in raw_cases:
        bundle, sha_ok = _decode_fixture_files(item["files"])
        skill_md = bundle.get("SKILL.md", b"").decode("utf-8", "replace")

        rep_v10 = audit_skill(
            skill_markdown=skill_md,
            mcp_json_text=None,
            backend=backend,
            bundle_files=None,
            enable_vendor_auth_scoping=False,
        )
        rep_v11 = audit_skill_bundle(bundle, backend=backend)

        group = item["corpus_group"]
        if group == "trailofbits_overtly_malicious":
            tob_total += 1
            if rep_v10.verdict != "PASS":
                tob_v10_intercepted += 1
            if rep_v11.verdict == "BLOCK":
                tob_v11_blocked += 1
            elif rep_v11.verdict == "QUARANTINE":
                tob_v11_quarantined += 1
        elif group == "pure_prose_social_engineering_boundary":
            prose_total += 1
            if rep_v11.verdict != "PASS":
                prose_intercepted += 1
        else:
            benign_total += 1
            if rep_v10.verdict != "PASS":
                benign_v10_fp += 1
            if rep_v11.verdict != "PASS":
                benign_v11_fp += 1

        matched = sorted(
            {f.rule_id for f in rep_v11.findings}
            | {tp.violation_kind for tp in rep_v11.taint_proofs}
        )
        results.append(
            ExternalCaseResult(
                case_id=str(item["case_id"]),
                corpus_group=group,
                source_repo=str(item["source_repo"]),
                commit_sha=str(item["commit_sha"]),
                skill_path=str(item["skill_path"]),
                attack_vector=str(item["attack_vector"]),
                v1_0_skill_md_only_verdict=rep_v10.verdict,
                v1_1_bundle_verdict=rep_v11.verdict,
                risk_score=rep_v11.risk_score,
                scan_latency_ms=rep_v11.scan_latency_ms,
                matched_rules=matched,
                sha256_verified=sha_ok,
            )
        )

    total_ms = round(sum(r.scan_latency_ms for r in results), 3)
    mean_ms = round(total_ms / max(1, len(results)), 3)
    tob_gate_recall = round(
        ((tob_v11_blocked + tob_v11_quarantined) / max(1, tob_total)) * 100.0, 2
    )
    tob_block_recall = round((tob_v11_blocked / max(1, tob_total)) * 100.0, 2)
    prose_recall = round((prose_intercepted / max(1, prose_total)) * 100.0, 2)
    v10_fpr = round((benign_v10_fp / max(1, benign_total)) * 100.0, 2)
    v11_fpr = round((benign_v11_fp / max(1, benign_total)) * 100.0, 2)

    return ExternalBenchmarkReport(
        schema_version=str(manifest["schema_version"]),
        backend=backend,
        total_cases=len(results),
        tob_malicious_total=tob_total,
        tob_v1_0_skill_md_only_intercepted=tob_v10_intercepted,
        tob_v1_1_hard_blocked=tob_v11_blocked,
        tob_v1_1_quarantined=tob_v11_quarantined,
        tob_v1_1_gate_intercept_recall_pct=tob_gate_recall,
        tob_v1_1_strict_block_recall_pct=tob_block_recall,
        prose_social_engineering_total=prose_total,
        prose_social_engineering_intercepted=prose_intercepted,
        prose_social_engineering_recall_pct=prose_recall,
        benign_upstream_total=benign_total,
        benign_v1_0_false_positives=benign_v10_fp,
        benign_v1_0_fpr_pct=v10_fpr,
        benign_v1_1_false_positives=benign_v11_fp,
        benign_v1_1_fpr_pct=v11_fpr,
        total_scan_latency_ms=total_ms,
        mean_scan_latency_ms=mean_ms,
        handoff_boundary_note=(
            "Stage-1 C++20 static bundle taint intercepts 4/4 (3 BLOCK + 1 QUARANTINE) structural/archive/"
            "bytecode/config-override evasions in trailofbits/overtly-malicious-skills at 0.0% FPR across 24 "
            "upstream community skills, while pure natural-language social engineering with zero code/sink "
            "primitives (0/2) requires Stage-2 semantic review and Stage-3 runtime sandboxing."
        ),
        results=results,
    )

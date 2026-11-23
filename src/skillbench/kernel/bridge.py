"""Zero-copy ctypes bridge to C++20 skill_taint_kernel + bit-exact Python fallback."""

from __future__ import annotations

import array
import ctypes
import platform
import shutil
import subprocess
from collections import deque
from dataclasses import dataclass
from pathlib import Path

ROLE_UNTRUSTED = 1
ROLE_SECRET = 2
ROLE_NET_SINK = 4
ROLE_EXEC_SINK = 8
ROLE_SANITIZER = 16


@dataclass(frozen=True)
class AcScanBatchResult:
    docs_flagged: int
    match_counts: list[int]
    category_masks: list[int]
    first_pattern_ids: list[int]
    bidi_trojan_counts: list[int]


@dataclass(frozen=True)
class TaintViolationTuple:
    src: int
    sink: int
    hops: int
    kind: int
    score: int


_LIB_CACHE: ctypes.CDLL | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _shared_lib_path() -> Path:
    ext = ".dylib" if platform.system() == "Darwin" else ".so"
    return _repo_root() / "csrc" / f"libskill_taint_kernel{ext}"


def ensure_native_lib(force_rebuild: bool = False) -> ctypes.CDLL:
    global _LIB_CACHE
    if _LIB_CACHE is not None and not force_rebuild:
        return _LIB_CACHE

    lib_path = _shared_lib_path()
    cpp_path = _repo_root() / "csrc" / "skill_taint_kernel.cpp"
    needs_build = (
        force_rebuild
        or not lib_path.exists()
        or cpp_path.stat().st_mtime > lib_path.stat().st_mtime
    )
    if needs_build:
        compiler = shutil.which("clang++") or shutil.which("g++")
        if compiler is None:  # pragma: no cover
            raise RuntimeError("Neither clang++ nor g++ found on PATH")
        cmd = [
            compiler,
            "-O3",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-shared",
            "-fPIC",
            str(cpp_path),
            "-o",
            str(lib_path),
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    lib = ctypes.CDLL(str(lib_path))
    lib.sb_ac_scan_corpus.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.sb_ac_scan_corpus.restype = ctypes.c_int32

    lib.sb_prove_taint_reachability.argtypes = [
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int32,
    ]
    lib.sb_prove_taint_reachability.restype = ctypes.c_int32

    _LIB_CACHE = lib
    return lib


def _count_utf8_trojans_py(buf: bytes) -> int:
    count = 0
    i = 0
    n = len(buf)
    while i + 2 < n:
        b0 = buf[i]
        b1 = buf[i + 1]
        b2 = buf[i + 2]
        if b0 == 0xE2 and b1 == 0x80 and ((0x8B <= b2 <= 0x8F) or (0xAA <= b2 <= 0xAE)):
            count += 1
            i += 3
            continue
        if b0 == 0xE2 and b1 == 0x81 and (0xA6 <= b2 <= 0xA9):
            count += 1
            i += 3
            continue
        if b0 == 0xEF and b1 == 0xBB and b2 == 0xBF:
            count += 1
            i += 3
            continue
        i += 1
    return count


def _ascii_lower_bytes(data: bytes) -> bytes:
    return bytes((b + 32 if 65 <= b <= 90 else b) for b in data)


def ac_scan_corpus_py(
    patterns: list[tuple[bytes, int]],
    docs: list[bytes],
) -> AcScanBatchResult:
    lowered_pats: list[tuple[int, bytes, int]] = [
        (idx, _ascii_lower_bytes(pat), cat)
        for idx, (pat, cat) in enumerate(patterns)
        if len(pat) > 0
    ]

    match_counts: list[int] = []
    category_masks: list[int] = []
    first_pattern_ids: list[int] = []
    bidi_trojan_counts: list[int] = []
    docs_flagged = 0

    for doc in docs:
        ldoc = _ascii_lower_bytes(doc)
        mcount = 0
        mask = 0
        min_pat = -1
        for idx, lpat, cat in lowered_pats:
            plen = len(lpat)
            start = 0
            while True:
                pos = ldoc.find(lpat, start)
                if pos == -1:
                    break
                mcount += 1
                if 0 <= cat < 31:
                    mask |= 1 << cat
                if min_pat == -1 or idx < min_pat:
                    min_pat = idx
                start = pos + 1
                if start + plen > len(ldoc):
                    break
        trojans = _count_utf8_trojans_py(doc)
        match_counts.append(mcount)
        category_masks.append(mask)
        first_pattern_ids.append(min_pat)
        bidi_trojan_counts.append(trojans)
        if mcount > 0 or trojans > 0:
            docs_flagged += 1

    return AcScanBatchResult(
        docs_flagged=docs_flagged,
        match_counts=match_counts,
        category_masks=category_masks,
        first_pattern_ids=first_pattern_ids,
        bidi_trojan_counts=bidi_trojan_counts,
    )


def ac_scan_corpus_cpp(
    patterns: list[tuple[bytes, int]],
    docs: list[bytes],
) -> AcScanBatchResult:
    if not docs:
        return AcScanBatchResult(0, [], [], [], [])

    lib = ensure_native_lib()
    pat_chunks = bytearray()
    pat_offsets = array.array("i")
    pat_lengths = array.array("i")
    pat_cats = array.array("i")
    for pat, cat in patterns:
        pat_offsets.append(len(pat_chunks))
        pat_lengths.append(len(pat))
        pat_cats.append(cat)
        pat_chunks.extend(pat)
    if not pat_chunks:
        pat_chunks.append(0)

    doc_chunks = bytearray()
    doc_offsets = array.array("i")
    doc_lengths = array.array("i")
    for doc in docs:
        doc_offsets.append(len(doc_chunks))
        doc_lengths.append(len(doc))
        doc_chunks.extend(doc)
    if not doc_chunks:
        doc_chunks.append(0)

    pat_buf = array.array("B", pat_chunks)
    doc_buf = array.array("B", doc_chunks)
    ndocs = len(docs)
    out_counts = array.array("i", [0] * ndocs)
    out_masks = array.array("I", [0] * ndocs)
    out_first = array.array("i", [-1] * ndocs)
    out_trojans = array.array("i", [0] * ndocs)

    flagged = int(
        lib.sb_ac_scan_corpus(
            pat_buf.buffer_info()[0],
            pat_offsets.buffer_info()[0] if len(pat_offsets) else 0,
            pat_lengths.buffer_info()[0] if len(pat_lengths) else 0,
            pat_cats.buffer_info()[0] if len(pat_cats) else 0,
            len(patterns),
            doc_buf.buffer_info()[0],
            doc_offsets.buffer_info()[0],
            doc_lengths.buffer_info()[0],
            ndocs,
            out_counts.buffer_info()[0],
            out_masks.buffer_info()[0],
            out_first.buffer_info()[0],
            out_trojans.buffer_info()[0],
        )
    )
    return AcScanBatchResult(
        docs_flagged=flagged,
        match_counts=list(out_counts),
        category_masks=list(out_masks),
        first_pattern_ids=list(out_first),
        bidi_trojan_counts=list(out_trojans),
    )


def prove_taint_reachability_py(
    node_roles: list[int],
    node_risk_weights: list[int],
    edges: list[tuple[int, int]],
) -> list[TaintViolationTuple]:
    num_nodes = len(node_roles)
    if num_nodes == 0:
        return []

    adj_sets: list[set[int]] = [set() for _ in range(num_nodes)]
    for u, v in edges:
        if 0 <= u < num_nodes and 0 <= v < num_nodes and u != v:
            adj_sets[u].add(v)
    adj = [sorted(s) for s in adj_sets]

    rules = (
        (ROLE_UNTRUSTED, ROLE_EXEC_SINK, 1),
        (ROLE_UNTRUSTED, ROLE_NET_SINK, 2),
        (ROLE_SECRET, ROLE_NET_SINK, 3),
        (ROLE_SECRET, ROLE_EXEC_SINK, 4),
    )

    violations: list[TaintViolationTuple] = []
    for s in range(num_nodes):
        s_role = node_roles[s]
        if (s_role & (ROLE_UNTRUSTED | ROLE_SECRET)) == 0:
            continue
        if (s_role & ROLE_SANITIZER) != 0:
            continue

        dist = [-1] * num_nodes
        max_risk = [0] * num_nodes
        dist[s] = 0
        max_risk[s] = max(0, min(100, node_risk_weights[s]))
        q: deque[int] = deque([s])

        while q:
            u = q.popleft()
            if u != s and (node_roles[u] & ROLE_SANITIZER) != 0:
                continue
            for v in adj[u]:
                if (node_roles[v] & ROLE_SANITIZER) != 0:
                    continue
                cand_risk = min(100, max_risk[u] + max(0, node_risk_weights[v]) // 2)
                if dist[v] == -1:
                    dist[v] = dist[u] + 1
                    max_risk[v] = cand_risk
                    q.append(v)

        for t in range(num_nodes):
            if t == s or dist[t] <= 0:
                continue
            t_role = node_roles[t]
            for req_src, req_sink, kind_code in rules:
                if (s_role & req_src) != 0 and (t_role & req_sink) != 0:
                    violations.append(
                        TaintViolationTuple(
                            src=s,
                            sink=t,
                            hops=dist[t],
                            kind=kind_code,
                            score=max_risk[t],
                        )
                    )
    return violations


def prove_taint_reachability_cpp(
    node_roles: list[int],
    node_risk_weights: list[int],
    edges: list[tuple[int, int]],
    max_violations: int = 4096,
) -> list[TaintViolationTuple]:
    num_nodes = len(node_roles)
    if num_nodes == 0:
        return []

    lib = ensure_native_lib()
    roles_arr = array.array("i", node_roles)
    risks_arr = array.array("i", node_risk_weights)
    src_arr = array.array("i", [u for u, _ in edges]) if edges else array.array("i", [0])
    dst_arr = array.array("i", [v for _, v in edges]) if edges else array.array("i", [0])

    cap = max(1, max_violations)
    out_src = array.array("i", [0] * cap)
    out_sink = array.array("i", [0] * cap)
    out_hops = array.array("i", [0] * cap)
    out_kind = array.array("i", [0] * cap)
    out_score = array.array("i", [0] * cap)

    total = int(
        lib.sb_prove_taint_reachability(
            num_nodes,
            roles_arr.buffer_info()[0],
            risks_arr.buffer_info()[0],
            src_arr.buffer_info()[0],
            dst_arr.buffer_info()[0],
            len(edges),
            out_src.buffer_info()[0],
            out_sink.buffer_info()[0],
            out_hops.buffer_info()[0],
            out_kind.buffer_info()[0],
            out_score.buffer_info()[0],
            cap,
        )
    )
    limit = min(total, cap)
    return [
        TaintViolationTuple(
            src=int(out_src[i]),
            sink=int(out_sink[i]),
            hops=int(out_hops[i]),
            kind=int(out_kind[i]),
            score=int(out_score[i]),
        )
        for i in range(limit)
    ]

"""C++20 Aho-Corasick & Taint-Reachability Kernel Bridge + Pure-Python Fallback."""

from skillbench.kernel.bridge import (
    ROLE_EXEC_SINK,
    ROLE_NET_SINK,
    ROLE_SANITIZER,
    ROLE_SECRET,
    ROLE_UNTRUSTED,
    AcScanBatchResult,
    TaintViolationTuple,
    ac_scan_corpus_cpp,
    ac_scan_corpus_py,
    ensure_native_lib,
    prove_taint_reachability_cpp,
    prove_taint_reachability_py,
)

__all__ = [
    "ROLE_UNTRUSTED",
    "ROLE_SECRET",
    "ROLE_NET_SINK",
    "ROLE_EXEC_SINK",
    "ROLE_SANITIZER",
    "AcScanBatchResult",
    "TaintViolationTuple",
    "ac_scan_corpus_cpp",
    "ac_scan_corpus_py",
    "ensure_native_lib",
    "prove_taint_reachability_cpp",
    "prove_taint_reachability_py",
]

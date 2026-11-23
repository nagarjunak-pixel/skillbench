"""Hypothesis property-based parity tests for C++20 vs Python kernels."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from skillbench.kernel.bridge import (
    ROLE_EXEC_SINK,
    ROLE_NET_SINK,
    ROLE_SANITIZER,
    ROLE_SECRET,
    ROLE_UNTRUSTED,
    ac_scan_corpus_cpp,
    ac_scan_corpus_py,
    ensure_native_lib,
    prove_taint_reachability_cpp,
    prove_taint_reachability_py,
)


def test_empty_and_rebuild_edge_cases() -> None:
    lib = ensure_native_lib(force_rebuild=True)
    assert lib is not None
    assert ac_scan_corpus_cpp([], []) == ac_scan_corpus_py([], [])
    assert ac_scan_corpus_cpp([], [b"hello", b""]) == ac_scan_corpus_py([], [b"hello", b""])
    assert ac_scan_corpus_cpp([(b"", 0)], [b""]) == ac_scan_corpus_py([(b"", 0)], [b""])
    assert prove_taint_reachability_cpp([], [], []) == []
    assert prove_taint_reachability_py([], [], []) == []


def test_utf8_bidi_trojan_parity() -> None:
    docs = [
        b"clean ascii text",
        "zero-width \u200b and \u200f hidden".encode(),
        "rtl override \u202e evil \u202c".encode(),
        "isolate \u2066 test \u2069 and bom \ufeff".encode(),
    ]
    pats = [(b"evil", 2), (b"clean", 0)]
    assert ac_scan_corpus_cpp(pats, docs) == ac_scan_corpus_py(pats, docs)


@settings(max_examples=80, deadline=None)
@given(
    patterns=st.lists(
        st.tuples(
            st.binary(min_size=0, max_size=8),
            st.integers(min_value=-1, max_value=32),
        ),
        min_size=0,
        max_size=15,
    ),
    docs=st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=20),
)
def test_hypothesis_ac_scan_parity(
    patterns: list[tuple[bytes, int]],
    docs: list[bytes],
) -> None:
    cpp_res = ac_scan_corpus_cpp(patterns, docs)
    py_res = ac_scan_corpus_py(patterns, docs)
    assert cpp_res == py_res


@settings(max_examples=80, deadline=None)
@given(
    roles=st.lists(
        st.sampled_from(
            [
                0,
                ROLE_UNTRUSTED,
                ROLE_SECRET,
                ROLE_NET_SINK,
                ROLE_EXEC_SINK,
                ROLE_SANITIZER,
                ROLE_UNTRUSTED | ROLE_SANITIZER,
                ROLE_UNTRUSTED | ROLE_NET_SINK,
            ]
        ),
        min_size=1,
        max_size=18,
    ),
    weights=st.lists(st.integers(min_value=-10, max_value=120), min_size=18, max_size=18),
    raw_edges=st.lists(
        st.tuples(st.integers(min_value=-1, max_value=20), st.integers(min_value=-1, max_value=20)),
        min_size=0,
        max_size=40,
    ),
)
def test_hypothesis_taint_reachability_parity(
    roles: list[int],
    weights: list[int],
    raw_edges: list[tuple[int, int]],
) -> None:
    trimmed_weights = weights[: len(roles)]
    cpp_v = prove_taint_reachability_cpp(roles, trimmed_weights, raw_edges)
    py_v = prove_taint_reachability_py(roles, trimmed_weights, raw_edges)
    assert cpp_v == py_v

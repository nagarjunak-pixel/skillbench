#include <algorithm>
#include <array>
#include <cstdint>
#include <queue>
#include <vector>

namespace {

inline uint8_t ascii_lower(uint8_t b) noexcept {
    return (b >= 'A' && b <= 'Z') ? static_cast<uint8_t>(b + 32) : b;
}

struct AcNode {
    std::array<int32_t, 256> next{};
    int32_t fail = 0;
    uint32_t cat_mask = 0;
    int32_t match_count = 0;
    int32_t min_pat_id = -1;

    AcNode() {
        next.fill(-1);
    }
};

inline int32_t count_utf8_trojans(const uint8_t* buf, int32_t len) noexcept {
    int32_t count = 0;
    for (int32_t i = 0; i + 2 < len; ++i) {
        const uint8_t b0 = buf[i];
        const uint8_t b1 = buf[i + 1];
        const uint8_t b2 = buf[i + 2];
        if (b0 == 0xE2 && b1 == 0x80) {
            if ((b2 >= 0x8B && b2 <= 0x8F) || (b2 >= 0xAA && b2 <= 0xAE)) {
                ++count;
                i += 2;
            }
        } else if (b0 == 0xE2 && b1 == 0x81) {
            if (b2 >= 0xA6 && b2 <= 0xA9) {
                ++count;
                i += 2;
            }
        } else if (b0 == 0xEF && b1 == 0xBB && b2 == 0xBF) {
            ++count;
            i += 2;
        }
    }
    return count;
}

}  // namespace

extern "C" {

int32_t sb_ac_scan_corpus(
    const uint8_t* patterns_flat,
    const int32_t* pattern_offsets,
    const int32_t* pattern_lengths,
    const int32_t* pattern_categories,
    int32_t num_patterns,
    const uint8_t* corpus_flat,
    const int32_t* doc_offsets,
    const int32_t* doc_lengths,
    int32_t num_docs,
    int32_t* out_match_counts,
    uint32_t* out_category_masks,
    int32_t* out_first_pattern_id,
    int32_t* out_bidi_trojan_counts
) {
    if (num_docs < 0 || num_patterns < 0) {
        return -1;
    }

    std::vector<AcNode> nodes;
    nodes.reserve(static_cast<size_t>(std::max(1, num_patterns * 12)));
    nodes.emplace_back();

    for (int32_t p = 0; p < num_patterns; ++p) {
        const int32_t off = pattern_offsets[p];
        const int32_t plen = pattern_lengths[p];
        if (plen <= 0) {
            continue;
        }
        int32_t cur = 0;
        for (int32_t j = 0; j < plen; ++j) {
            const uint8_t ch = ascii_lower(patterns_flat[off + j]);
            int32_t nxt = nodes[static_cast<size_t>(cur)].next[ch];
            if (nxt == -1) {
                nxt = static_cast<int32_t>(nodes.size());
                nodes[static_cast<size_t>(cur)].next[ch] = nxt;
                nodes.emplace_back();
            }
            cur = nxt;
        }
        AcNode& leaf = nodes[static_cast<size_t>(cur)];
        const int32_t cat = pattern_categories[p];
        if (cat >= 0 && cat < 31) {
            leaf.cat_mask |= (1u << static_cast<uint32_t>(cat));
        }
        leaf.match_count += 1;
        if (leaf.min_pat_id == -1 || p < leaf.min_pat_id) {
            leaf.min_pat_id = p;
        }
    }

    std::queue<int32_t> q;
    for (int32_t c = 0; c < 256; ++c) {
        int32_t nxt = nodes[0].next[static_cast<size_t>(c)];
        if (nxt != -1) {
            nodes[static_cast<size_t>(nxt)].fail = 0;
            q.push(nxt);
        } else {
            nodes[0].next[static_cast<size_t>(c)] = 0;
        }
    }

    while (!q.empty()) {
        const int32_t u = q.front();
        q.pop();
        const int32_t f = nodes[static_cast<size_t>(u)].fail;
        nodes[static_cast<size_t>(u)].cat_mask |= nodes[static_cast<size_t>(f)].cat_mask;
        nodes[static_cast<size_t>(u)].match_count += nodes[static_cast<size_t>(f)].match_count;
        const int32_t f_min = nodes[static_cast<size_t>(f)].min_pat_id;
        if (f_min != -1) {
            int32_t& u_min = nodes[static_cast<size_t>(u)].min_pat_id;
            if (u_min == -1 || f_min < u_min) {
                u_min = f_min;
            }
        }
        for (int32_t c = 0; c < 256; ++c) {
            int32_t nxt = nodes[static_cast<size_t>(u)].next[static_cast<size_t>(c)];
            if (nxt != -1) {
                nodes[static_cast<size_t>(nxt)].fail =
                    nodes[static_cast<size_t>(f)].next[static_cast<size_t>(c)];
                q.push(nxt);
            } else {
                nodes[static_cast<size_t>(u)].next[static_cast<size_t>(c)] =
                    nodes[static_cast<size_t>(f)].next[static_cast<size_t>(c)];
            }
        }
    }

    int32_t docs_flagged = 0;
    for (int32_t d = 0; d < num_docs; ++d) {
        const uint8_t* ptr = corpus_flat + doc_offsets[d];
        const int32_t dlen = doc_lengths[d];

        int32_t state = 0;
        int32_t mcount = 0;
        uint32_t mask = 0;
        int32_t min_pat = -1;

        for (int32_t i = 0; i < dlen; ++i) {
            const uint8_t ch = ascii_lower(ptr[i]);
            state = nodes[static_cast<size_t>(state)].next[ch];
            const AcNode& nd = nodes[static_cast<size_t>(state)];
            if (nd.match_count > 0) {
                mcount += nd.match_count;
                mask |= nd.cat_mask;
                if (nd.min_pat_id != -1 && (min_pat == -1 || nd.min_pat_id < min_pat)) {
                    min_pat = nd.min_pat_id;
                }
            }
        }

        const int32_t trojans = count_utf8_trojans(ptr, dlen);
        out_match_counts[d] = mcount;
        out_category_masks[d] = mask;
        out_first_pattern_id[d] = min_pat;
        out_bidi_trojan_counts[d] = trojans;
        if (mcount > 0 || trojans > 0) {
            ++docs_flagged;
        }
    }

    return docs_flagged;
}

int32_t sb_prove_taint_reachability(
    int32_t num_nodes,
    const int32_t* node_roles,
    const int32_t* node_risk_weights,
    const int32_t* edge_src,
    const int32_t* edge_dst,
    int32_t num_edges,
    int32_t* out_src,
    int32_t* out_sink,
    int32_t* out_hops,
    int32_t* out_kind,
    int32_t* out_score,
    int32_t max_violations
) {
    if (num_nodes <= 0 || num_edges < 0 || max_violations < 0) {
        return 0;
    }

    constexpr int32_t ROLE_UNTRUSTED = 1;
    constexpr int32_t ROLE_SECRET = 2;
    constexpr int32_t ROLE_NET_SINK = 4;
    constexpr int32_t ROLE_EXEC_SINK = 8;
    constexpr int32_t ROLE_SANITIZER = 16;

    std::vector<std::vector<int32_t>> adj(static_cast<size_t>(num_nodes));
    for (int32_t e = 0; e < num_edges; ++e) {
        const int32_t u = edge_src[e];
        const int32_t v = edge_dst[e];
        if (u >= 0 && u < num_nodes && v >= 0 && v < num_nodes && u != v) {
            adj[static_cast<size_t>(u)].push_back(v);
        }
    }
    for (auto& nbrs : adj) {
        std::sort(nbrs.begin(), nbrs.end());
        nbrs.erase(std::unique(nbrs.begin(), nbrs.end()), nbrs.end());
    }

    int32_t total = 0;
    std::vector<int32_t> dist(static_cast<size_t>(num_nodes), -1);
    std::vector<int32_t> max_path_risk(static_cast<size_t>(num_nodes), 0);

    for (int32_t s = 0; s < num_nodes; ++s) {
        const int32_t s_role = node_roles[s];
        if ((s_role & (ROLE_UNTRUSTED | ROLE_SECRET)) == 0) {
            continue;
        }
        if ((s_role & ROLE_SANITIZER) != 0) {
            continue;
        }

        std::fill(dist.begin(), dist.end(), -1);
        std::fill(max_path_risk.begin(), max_path_risk.end(), 0);
        std::queue<int32_t> q;
        dist[static_cast<size_t>(s)] = 0;
        max_path_risk[static_cast<size_t>(s)] = std::clamp(node_risk_weights[s], 0, 100);
        q.push(s);

        while (!q.empty()) {
            const int32_t u = q.front();
            q.pop();
            if (u != s && (node_roles[u] & ROLE_SANITIZER) != 0) {
                continue;
            }
            for (const int32_t v : adj[static_cast<size_t>(u)]) {
                if ((node_roles[v] & ROLE_SANITIZER) != 0) {
                    continue;
                }
                const int32_t cand_risk = std::min(
                    100,
                    max_path_risk[static_cast<size_t>(u)] + std::max(0, node_risk_weights[v]) / 2
                );
                if (dist[static_cast<size_t>(v)] == -1) {
                    dist[static_cast<size_t>(v)] = dist[static_cast<size_t>(u)] + 1;
                    max_path_risk[static_cast<size_t>(v)] = cand_risk;
                    q.push(v);
                }
            }
        }

        for (int32_t t = 0; t < num_nodes; ++t) {
            if (t == s || dist[static_cast<size_t>(t)] <= 0) {
                continue;
            }
            const int32_t t_role = node_roles[t];
            const std::array<std::pair<int32_t, int32_t>, 4> rules = {{
                {ROLE_UNTRUSTED | ROLE_EXEC_SINK, 1},
                {ROLE_UNTRUSTED | ROLE_NET_SINK, 2},
                {ROLE_SECRET | ROLE_NET_SINK, 3},
                {ROLE_SECRET | ROLE_EXEC_SINK, 4},
            }};
            for (const auto& [mask_pair, kind_code] : rules) {
                const int32_t req_src = mask_pair & (ROLE_UNTRUSTED | ROLE_SECRET);
                const int32_t req_sink = mask_pair & (ROLE_NET_SINK | ROLE_EXEC_SINK);
                if ((s_role & req_src) != 0 && (t_role & req_sink) != 0) {
                    if (total < max_violations) {
                        out_src[total] = s;
                        out_sink[total] = t;
                        out_hops[total] = dist[static_cast<size_t>(t)];
                        out_kind[total] = kind_code;
                        out_score[total] = max_path_risk[static_cast<size_t>(t)];
                    }
                    ++total;
                }
            }
        }
    }

    return total;
}

}  // extern "C"

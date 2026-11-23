"""Parser compiling SKILL.md & .mcp.json definitions into AST layers and taint graphs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

from skillbench.kernel.bridge import (
    ROLE_EXEC_SINK,
    ROLE_NET_SINK,
    ROLE_SANITIZER,
    ROLE_SECRET,
    ROLE_UNTRUSTED,
)
from skillbench.models import SkillBomComponent, SkillEdge, SkillNode

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_CODE_FENCE_RE = re.compile(r"```([A-Za-z0-9_+-]*)\n(.*?)```", re.DOTALL)
_B64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")

_UNTRUSTED_HINTS = (
    "github_issue",
    "pull_request",
    "untrusted",
    "web_fetch",
    "scrape_url",
    "inbound_email",
    "user_upload",
    "ticket_body",
    "external_doc",
)
_SECRET_HINTS = (
    ".aws/credentials",
    ".ssh/id_rsa",
    ".env",
    "api_key",
    "secret_key",
    "kubeconfig",
    "access_token",
    "private_key",
    "read_secret",
    "vault_token",
)
_SANITIZER_HINTS = (
    "pydantic_validate",
    "schema_sanitize",
    "allowlist_filter",
    "redact_pii",
    "hmac_verify",
    "parameterized_query",
)
_NET_SINK_HINTS = (
    "curl ",
    "wget ",
    "http://",
    "https://",
    "webhook",
    "requests.post",
    "httpx.post",
    "fetch(",
    "send_slack",
    "post_external",
    "ngrok",
    "burpcollaborator",
)
_EXEC_SINK_HINTS = (
    "bash -c",
    "sh -c",
    "subprocess.run",
    "os.system",
    "eval(",
    "exec(",
    "chmod +x",
    "| sh",
    "| bash",
    "run_shell",
    "execute_command",
)


@dataclass(frozen=True)
class ParsedSkillArtifact:
    skill_name: str
    description: str
    artifact_sha256: str
    raw_bytes: bytes
    comment_blocks: list[str]
    decoded_base64_blobs: list[str]
    code_blocks: list[tuple[str, str]]
    mcp_tool_descriptions: list[tuple[str, str]]
    nodes: list[SkillNode]
    edges: list[SkillEdge]
    bom: list[SkillBomComponent]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_frontmatter(text: str) -> tuple[str, str]:
    name = "unnamed-skill"
    desc = ""
    m = _FRONTMATTER_RE.match(text)
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                key = k.strip().lower()
                val = v.strip().strip("\"'")
                if key == "name" and val:
                    name = val
                elif key == "description" and val:
                    desc = val
    return name, desc


def _extract_valid_base64(text: str) -> list[str]:
    decoded: list[str] = []
    seen: set[str] = set()
    for match in _B64_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        if len(token) % 4 != 0 or token in seen:
            continue
        seen.add(token)
        try:
            raw = base64.b64decode(token, validate=True)
            as_utf8 = raw.decode("utf-8")
        except Exception:
            continue
        printable_ratio = sum(1 for ch in as_utf8 if ch.isprintable() or ch in "\r\n\t") / max(
            1, len(as_utf8)
        )
        if len(as_utf8.strip()) >= 8 and printable_ratio >= 0.85:
            decoded.append(as_utf8)
    return decoded


def _classify_step(name: str, body: str) -> tuple[SkillNode | None, int]:
    low = f"{name}\n{body}".lower()
    has_untrusted = any(h in low for h in _UNTRUSTED_HINTS)
    has_secret = any(h in low for h in _SECRET_HINTS)
    has_sanitizer = any(h in low for h in _SANITIZER_HINTS)
    has_net = any(h in low for h in _NET_SINK_HINTS)
    has_exec = any(h in low for h in _EXEC_SINK_HINTS)

    mask = 0
    if has_untrusted:
        mask |= ROLE_UNTRUSTED
    if has_secret:
        mask |= ROLE_SECRET
    if has_sanitizer and not (has_secret or has_exec):
        mask |= ROLE_SANITIZER
    if has_net:
        mask |= ROLE_NET_SINK
    if has_exec:
        mask |= ROLE_EXEC_SINK

    if mask == 0:
        return None, 0

    if mask & ROLE_SECRET:
        kind = "source_secret"
        risk = 80
    elif mask & ROLE_UNTRUSTED:
        kind = "source_untrusted"
        risk = 65
    elif mask & ROLE_SANITIZER:
        kind = "sanitizer"
        risk = 0
    elif mask & ROLE_EXEC_SINK:
        kind = "sink_exec"
        risk = 85
    else:
        kind = "sink_net"
        risk = 75

    snippet = body.strip().splitlines()[0][:90] if body.strip() else name
    node = SkillNode(
        node_id=0,
        name=name,
        kind=kind,  # type: ignore[arg-type]
        role_mask=mask,
        risk_weight=risk,
        evidence=snippet,
    )
    return node, mask


def compile_skill_artifact(
    skill_markdown: str,
    mcp_json_text: str | None = None,
) -> ParsedSkillArtifact:
    combined_bytes = (skill_markdown + ("\n" + mcp_json_text if mcp_json_text else "")).encode(
        "utf-8"
    )
    digest = _sha256_hex(combined_bytes)
    skill_name, desc = _parse_frontmatter(skill_markdown)

    comments = [
        m.group(1).strip() for m in _HTML_COMMENT_RE.finditer(skill_markdown) if m.group(1).strip()
    ]
    code_blocks = [
        (m.group(1).strip() or "text", m.group(2)) for m in _CODE_FENCE_RE.finditer(skill_markdown)
    ]
    b64_blobs = _extract_valid_base64(
        skill_markdown + ("\n" + mcp_json_text if mcp_json_text else "")
    )

    mcp_tools: list[tuple[str, str]] = []
    bom: list[SkillBomComponent] = [
        SkillBomComponent(
            component_type="skill",
            name=skill_name,
            sha256=_sha256_hex(skill_markdown.encode("utf-8")),
            capabilities=["markdown_instructions"],
        )
    ]

    explicit_flows: list[tuple[str, str]] = []
    if mcp_json_text and mcp_json_text.strip():
        parsed = json.loads(mcp_json_text)
        servers = parsed.get("mcpServers", {}) if isinstance(parsed, dict) else {}
        if isinstance(servers, dict):
            for srv_name, srv_cfg in servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                cmd_str = f"{srv_cfg.get('command', '')} {' '.join(str(x) for x in srv_cfg.get('args', []))}"
                bom.append(
                    SkillBomComponent(
                        component_type="mcp_server",
                        name=str(srv_name),
                        sha256=_sha256_hex(json.dumps(srv_cfg, sort_keys=True).encode("utf-8")),
                        capabilities=[cmd_str.strip() or "stdio"],
                    )
                )
                mcp_tools.append((f"server:{srv_name}", cmd_str))
        tools_arr = parsed.get("tools", []) if isinstance(parsed, dict) else []
        if isinstance(tools_arr, list):
            for tool_obj in tools_arr:
                if not isinstance(tool_obj, dict):
                    continue
                tname = str(tool_obj.get("name", "unnamed_tool"))
                tdesc = str(tool_obj.get("description", ""))
                mcp_tools.append((tname, tdesc))
                bom.append(
                    SkillBomComponent(
                        component_type="mcp_tool",
                        name=tname,
                        sha256=_sha256_hex(json.dumps(tool_obj, sort_keys=True).encode("utf-8")),
                        capabilities=[str(x) for x in tool_obj.get("capabilities", [])]
                        or ["tool_call"],
                    )
                )
                feeds_into = tool_obj.get("feeds_into", [])
                if isinstance(feeds_into, list):
                    for dst_name in feeds_into:
                        explicit_flows.append((tname, str(dst_name)))

    nodes: list[SkillNode] = []
    name_to_id: dict[str, int] = {}

    def _add_node(candidate: SkillNode) -> int:
        nid = len(nodes)
        assigned = candidate.model_copy(update={"node_id": nid})
        nodes.append(assigned)
        name_to_id[assigned.name] = nid
        return nid

    # Extract sequential steps from sections/code blocks/decoded blobs/comments
    step_items: list[tuple[str, str]] = []
    for idx, (lang, code) in enumerate(code_blocks):
        bom.append(
            SkillBomComponent(
                component_type="code_block",
                name=f"code_block_{idx}_{lang}",
                sha256=_sha256_hex(code.encode("utf-8")),
                capabilities=[lang],
            )
        )
        for l_idx, line in enumerate(code.splitlines()):
            if line.strip() and not line.strip().startswith("#"):
                step_items.append((f"code[{idx}:{l_idx}]", line.strip()))

    for idx, ctext in enumerate(comments):
        step_items.append((f"html_comment[{idx}]", ctext))
    for idx, btext in enumerate(b64_blobs):
        step_items.append((f"base64_payload[{idx}]", btext))
    for tname, tdesc in mcp_tools:
        step_items.append((tname, tdesc))

    flow_referenced = {u for u, _ in explicit_flows} | {v for _, v in explicit_flows}
    ordered_step_ids: list[int] = []
    for sname, sbody in step_items:
        classified, mask = _classify_step(sname, sbody)
        if classified is None and sname in flow_referenced:
            classified = SkillNode(
                node_id=0,
                name=sname,
                kind="transform",
                role_mask=0,
                risk_weight=10,
                evidence=(sbody.strip().splitlines()[0][:90] if sbody.strip() else sname),
            )
        if classified is not None:
            # If a single line both reads a secret/untrusted input AND pipes to net/exec sink, split into source -> sink!
            src_bits = mask & (ROLE_UNTRUSTED | ROLE_SECRET)
            sink_bits = mask & (ROLE_NET_SINK | ROLE_EXEC_SINK)
            if src_bits and sink_bits:
                src_kind = "source_secret" if (src_bits & ROLE_SECRET) else "source_untrusted"
                sink_kind = "sink_exec" if (sink_bits & ROLE_EXEC_SINK) else "sink_net"
                src_id = _add_node(
                    SkillNode(
                        node_id=0,
                        name=f"{sname}:source",
                        kind=src_kind,  # type: ignore[arg-type]
                        role_mask=src_bits,
                        risk_weight=85 if (src_bits & ROLE_SECRET) else 70,
                        evidence=sbody[:90],
                    )
                )
                sink_id = _add_node(
                    SkillNode(
                        node_id=0,
                        name=f"{sname}:sink",
                        kind=sink_kind,  # type: ignore[arg-type]
                        role_mask=sink_bits,
                        risk_weight=85,
                        evidence=sbody[:90],
                    )
                )
                ordered_step_ids.extend([src_id, sink_id])
            else:
                nid = _add_node(classified)
                ordered_step_ids.append(nid)

    edges: list[SkillEdge] = []
    # Connect explicit MCP tool flows if declared, otherwise sequential workflow order inside skill
    if explicit_flows:
        for src_name, dst_name in explicit_flows:
            if src_name in name_to_id and dst_name in name_to_id:
                edges.append(
                    SkillEdge(
                        src=name_to_id[src_name],
                        dst=name_to_id[dst_name],
                        reason="explicit_mcp_dataflow",
                    )
                )
    for i in range(len(ordered_step_ids) - 1):
        u_id = ordered_step_ids[i]
        v_id = ordered_step_ids[i + 1]
        # Avoid linking two unrelated MCP tool definitions unless explicit_flows is absent
        if (
            explicit_flows
            and not nodes[u_id].name.startswith(("code[", "html_comment[", "base64_payload["))
            and not nodes[u_id].name.endswith(":source")
        ):
            continue
        edges.append(SkillEdge(src=u_id, dst=v_id, reason="sequential_skill_pipeline"))

    return ParsedSkillArtifact(
        skill_name=skill_name,
        description=desc,
        artifact_sha256=digest,
        raw_bytes=combined_bytes,
        comment_blocks=comments,
        decoded_base64_blobs=b64_blobs,
        code_blocks=code_blocks,
        mcp_tool_descriptions=mcp_tools,
        nodes=nodes,
        edges=edges,
        bom=bom,
    )

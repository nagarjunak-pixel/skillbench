"""Parser compiling SKILL.md, .mcp.json & multi-file skill bundles into AST layers and taint graphs."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import posixpath
import re
import zipfile
from dataclasses import dataclass, field

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
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")
_ASCII_STR_RE = re.compile(rb"[ -~]{4,}")
_XML_TAG_RE = re.compile(r"<[^>]+>")
_REGISTRY_URL_RE = re.compile(
    r"(?:registry\s*=?\s*|corp_registry\s*=\s*|index-url\s*=\s*)[\"']?(https?://[A-Za-z0-9.-]+)",
    re.IGNORECASE,
)

_MAX_ZIP_ENTRIES = 64
_MAX_ZIP_EXTRACT_BYTES = 4 * 1024 * 1024

_VENDOR_SCOPED_KEY_HOSTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("developerknowledge_api_key", ("developerknowledge.googleapis.com", "developers.google.com")),
    ("google_api_key", ("googleapis.com",)),
    ("gemini_api_key", ("generativelanguage.googleapis.com", "googleapis.com")),
    ("openai_api_key", ("api.openai.com",)),
    ("anthropic_api_key", ("api.anthropic.com",)),
    ("github_token", ("api.github.com",)),
    ("cloudflare_api_token", ("api.cloudflare.com",)),
)

_STANDARD_PUBLIC_REGISTRIES = frozenset(
    {
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "files.pythonhosted.org",
    }
)

_HIGH_RISK_PYC_SYMBOLS = frozenset(
    {"environ", "eval", "exec", "subprocess", "socket", "urlopen", "Popen", "system"}
)

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
    "os.environ",
    "api_key",
    "secret_key",
    "kubeconfig",
    "access_token",
    "private_key",
    "read_secret",
    "vault_token",
)
_HARD_FILE_SECRET_HINTS = (
    ".aws/credentials",
    ".ssh/id_rsa",
    ".env",
    "os.environ",
    "kubeconfig",
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
class BytecodeAuditInfo:
    rel_path: str
    sibling_source_path: str | None
    divergent_symbols: tuple[str, ...]


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
    companion_scripts: list[tuple[str, bytes]] = field(default_factory=list)
    archive_texts: list[tuple[str, bytes]] = field(default_factory=list)
    embedded_archive_scripts: list[tuple[str, str]] = field(default_factory=list)
    bytecode_artifacts: list[BytecodeAuditInfo] = field(default_factory=list)
    unverified_registries: list[tuple[str, str]] = field(default_factory=list)
    git_hook_writes: list[str] = field(default_factory=list)


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


def _join_shell_continuations(code: str) -> list[str]:
    logical: list[str] = []
    buf = ""
    for raw_line in code.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            if buf:
                logical.append(buf)
                buf = ""
            continue
        if stripped.endswith("\\"):
            buf = f"{buf} {stripped[:-1].strip()}".strip()
        else:
            buf = f"{buf} {stripped}".strip() if buf else stripped
            logical.append(buf)
            buf = ""
    if buf:
        logical.append(buf)
    return logical


def _is_domain_bound_vendor_auth(low_line: str) -> bool:
    """Return True when a command only passes a vendor-specific API key to its own first-party API host."""
    if any(h in low_line for h in _HARD_FILE_SECRET_HINTS):
        return False
    hosts = [m.group(1).lower() for m in _URL_HOST_RE.finditer(low_line)]
    if not hosts:
        return False
    for key_var, allowed_suffixes in _VENDOR_SCOPED_KEY_HOSTS:
        if key_var in low_line:
            return all(
                any(h == suf or h.endswith("." + suf) for suf in allowed_suffixes) for h in hosts
            )
    return False


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


def _classify_step(
    name: str, body: str, enable_vendor_auth_scoping: bool = True
) -> tuple[SkillNode | None, int]:
    low = f"{name}\n{body}".lower()
    if enable_vendor_auth_scoping and _is_domain_bound_vendor_auth(low):
        return None, 0

    # Ignore benign .env.example / .gitignore defensive hygiene lines unless real .env is read
    low_clean = (
        low.replace(".env.example", "")
        .replace(".env.local", "")
        .replace(".env.sample", "")
        .replace('for entry in ".env"', "for entry in env_ignore")
    )
    if ".gitignore" in low_clean:
        low_clean = low_clean.replace(".env", "env_ignored")

    has_untrusted = any(h in low_clean for h in _UNTRUSTED_HINTS)
    has_secret = any(h in low_clean for h in _SECRET_HINTS)
    has_sanitizer = any(h in low_clean for h in _SANITIZER_HINTS)
    has_net = any(h in low_clean for h in _NET_SINK_HINTS)
    has_exec = any(h in low_clean for h in _EXEC_SINK_HINTS)

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


def _find_sibling_py_source(pyc_rel_path: str, bundle_files: dict[str, bytes]) -> str | None:
    base = posixpath.basename(pyc_rel_path)
    stem = base.split(".", 1)[0]
    parent = posixpath.dirname(pyc_rel_path)
    if posixpath.basename(parent) == "__pycache__":
        parent = posixpath.dirname(parent)
    candidate = posixpath.join(parent, f"{stem}.py") if parent else f"{stem}.py"
    if candidate in bundle_files:
        return candidate
    return None


def _inspect_zip_container(
    rel_path: str, raw: bytes
) -> tuple[list[tuple[str, bytes]], list[tuple[str, str]]]:
    texts: list[tuple[str, bytes]] = []
    embedded_scripts: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()[:_MAX_ZIP_ENTRIES]
            budget = _MAX_ZIP_EXTRACT_BYTES
            for info in infos:
                if info.is_dir():
                    continue
                mname = info.filename
                low_name = mname.lower()
                if low_name.endswith((".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".js")):
                    embedded_scripts.append((rel_path, mname))
                if info.file_size > budget:
                    continue
                if low_name.endswith((".xml", ".rels", ".md", ".txt", ".sh", ".py", ".json")):
                    data = zf.read(info)
                    budget -= len(data)
                    if low_name.endswith((".xml", ".rels")):
                        xml_txt = data.decode("utf-8", "replace")
                        stripped = re.sub(r"\s+", " ", _XML_TAG_RE.sub(" ", xml_txt)).strip()
                        if stripped:
                            texts.append((f"{rel_path}!{mname}", stripped.encode("utf-8")))
                    else:
                        texts.append((f"{rel_path}!{mname}", data))
    except zipfile.BadZipFile:
        pass
    return texts, embedded_scripts


def compile_skill_artifact(
    skill_markdown: str,
    mcp_json_text: str | None = None,
    bundle_files: dict[str, bytes] | None = None,
    enable_vendor_auth_scoping: bool = True,
) -> ParsedSkillArtifact:
    hasher = hashlib.sha256()
    hasher.update(skill_markdown.encode("utf-8"))
    if mcp_json_text:
        hasher.update(b"\n")
        hasher.update(mcp_json_text.encode("utf-8"))
    if bundle_files:
        for k in sorted(bundle_files):
            hasher.update(k.encode("utf-8"))
            hasher.update(bundle_files[k])
    digest = hasher.hexdigest()

    combined_bytes = (skill_markdown + ("\n" + mcp_json_text if mcp_json_text else "")).encode(
        "utf-8"
    )
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

    companion_scripts: list[tuple[str, bytes]] = []
    archive_texts: list[tuple[str, bytes]] = []
    embedded_archive_scripts: list[tuple[str, str]] = []
    bytecode_artifacts: list[BytecodeAuditInfo] = []
    unverified_registries: list[tuple[str, str]] = []
    git_hook_writes: list[str] = []

    if bundle_files:
        for rel_path in sorted(bundle_files):
            if rel_path == "SKILL.md" or rel_path.endswith("/SKILL.md"):
                continue
            raw = bundle_files[rel_path]
            low_path = rel_path.lower()

            if raw[:4] == b"PK\x03\x04":
                bom.append(
                    SkillBomComponent(
                        component_type="archive_container",
                        name=rel_path,
                        sha256=_sha256_hex(raw),
                        capabilities=["pkzip_ooxml_container"],
                    )
                )
                z_texts, z_scripts = _inspect_zip_container(rel_path, raw)
                archive_texts.extend(z_texts)
                embedded_archive_scripts.extend(z_scripts)
                continue

            if low_path.endswith((".pyc", ".pyo", ".so", ".dylib", ".dll")):
                bom.append(
                    SkillBomComponent(
                        component_type="bytecode_artifact",
                        name=rel_path,
                        sha256=_sha256_hex(raw),
                        capabilities=["precompiled_binary"],
                    )
                )
                pyc_tokens = {
                    m.group(0).decode("ascii", "ignore") for m in _ASCII_STR_RE.finditer(raw)
                }
                sib_path = _find_sibling_py_source(rel_path, bundle_files)
                sib_txt = (
                    bundle_files[sib_path].decode("utf-8", "replace")
                    if sib_path is not None
                    else ""
                )
                divergent: list[str] = []
                for sym in sorted(_HIGH_RISK_PYC_SYMBOLS):
                    if any(sym in tok for tok in pyc_tokens) and sym not in sib_txt:
                        divergent.append(sym)
                bytecode_artifacts.append(
                    BytecodeAuditInfo(
                        rel_path=rel_path,
                        sibling_source_path=sib_path,
                        divergent_symbols=tuple(divergent),
                    )
                )
                continue

            if low_path.endswith((".py", ".sh", ".bash", ".js", ".ts", ".ps1", ".rb")):
                bom.append(
                    SkillBomComponent(
                        component_type="companion_script",
                        name=rel_path,
                        sha256=_sha256_hex(raw),
                        capabilities=["companion_script"],
                    )
                )
                companion_scripts.append((rel_path, raw))
                text_script = raw.decode("utf-8", "replace")
                if ".npmrc" in text_script or ".yarnrc" in text_script or "pip.conf" in text_script:
                    for rm in _REGISTRY_URL_RE.finditer(text_script):
                        url = rm.group(1)
                        host_m = _URL_HOST_RE.match(url)
                        host = host_m.group(1).lower() if host_m else ""
                        if host and host not in _STANDARD_PUBLIC_REGISTRIES:
                            unverified_registries.append((rel_path, url))
                if ".git/hooks" in text_script:
                    git_hook_writes.append(rel_path)

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
        lines = (
            _join_shell_continuations(code)
            if enable_vendor_auth_scoping
            else [
                ln.strip()
                for ln in code.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
        )
        for l_idx, line in enumerate(lines):
            step_items.append((f"code[{idx}:{l_idx}]", line))

    for idx, ctext in enumerate(comments):
        step_items.append((f"html_comment[{idx}]", ctext))
    for idx, btext in enumerate(b64_blobs):
        step_items.append((f"base64_payload[{idx}]", btext))
    for tname, tdesc in mcp_tools:
        step_items.append((tname, tdesc))
    for script_path, script_bytes in companion_scripts:
        script_txt = script_bytes.decode("utf-8", "replace")
        for l_idx, line in enumerate(_join_shell_continuations(script_txt)):
            step_items.append((f"script[{script_path}:{l_idx}]", line))

    flow_referenced = {u for u, _ in explicit_flows} | {v for _, v in explicit_flows}
    ordered_step_ids: list[int] = []
    for sname, sbody in step_items:
        classified, mask = _classify_step(
            sname, sbody, enable_vendor_auth_scoping=enable_vendor_auth_scoping
        )
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
        if (
            explicit_flows
            and not nodes[u_id].name.startswith(
                ("code[", "html_comment[", "base64_payload[", "script[")
            )
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
        companion_scripts=companion_scripts,
        archive_texts=archive_texts,
        embedded_archive_scripts=embedded_archive_scripts,
        bytecode_artifacts=bytecode_artifacts,
        unverified_registries=unverified_registries,
        git_hook_writes=git_hook_writes,
    )

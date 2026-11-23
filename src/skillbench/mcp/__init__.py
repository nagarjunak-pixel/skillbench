"""JSON-RPC 2.0 stdio MCP Server for SkillBench."""

from skillbench.mcp.server import handle_jsonrpc_message, run_stdio_server

__all__ = ["handle_jsonrpc_message", "run_stdio_server"]

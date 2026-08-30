"""An MCP server whose every tool call is authorized by renker-core-authz.

Point any MCP client (Claude Desktop, an IDE, your own agent loop) at this server.
The tools it exposes — ``read_file``, ``write_file``, ``delete_file`` — do not run
until the policy gateway authorizes them, and every decision lands in the audit log.
An action whose capability requires human approval is *surfaced, not executed*: the
tool returns ``REQUIRE_APPROVAL`` so the human on the client side decides.

Run it:

    pip install -e ".[mcp]"
    python -m renker_agent_demo.mcp_server        # stdio transport

Requires the optional ``mcp`` dependency. Everything else in this package (the
gateway, the scripted demo, the tests) runs without it.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from renker_core_authz import Actor, Capability, CapabilityStore, PathScope
from renker_core_authz.audit import AuditLog

from renker_agent_demo.gateway import PolicyGateway
from renker_agent_demo.tools import AgentTools

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as error:  # pragma: no cover - only hit without the extra installed
    raise SystemExit(
        "The MCP server needs the optional 'mcp' dependency:\n"
        "    pip install -e '.[mcp]'"
    ) from error

AGENT = Actor("agent", "mcp-session")


def _build_workspace() -> tuple[AgentTools, AuditLog, Path]:
    """A least-privilege sandbox: read the workspace, write only into drafts."""
    root = Path(tempfile.mkdtemp(prefix="renker-agent-demo-mcp-"))
    workspace = root / "workspace"
    (workspace / "drafts").mkdir(parents=True)

    now = datetime.now(UTC)
    store = CapabilityStore()
    store.grant(
        Capability(
            capability="filesystem.read",
            scope=PathScope(base=str(workspace)),
            granted_to=AGENT.urn,
            granted_by="human:owner",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    store.grant(
        Capability(
            capability="filesystem.write",
            scope=PathScope(base=str(workspace / "drafts")),
            granted_to=AGENT.urn,
            granted_by="human:owner",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            approval_policy="human",  # writes are surfaced for approval, never auto-run
        )
    )

    audit = AuditLog(root / "audit.log")
    # On the server side there is no interactive human, so approval is never auto-granted:
    # REQUIRE_APPROVAL is reported back to the client instead of executing.
    gateway = PolicyGateway(store, audit, approval_hook=lambda _result: False)
    return AgentTools(gateway, AGENT), audit, workspace


def create_server() -> FastMCP:
    tools, audit, workspace = _build_workspace()
    mcp = FastMCP("renker-agent-demo")

    def _format(outcome: object) -> str:
        text = f"{outcome.decision} - {outcome.reason}"  # type: ignore[attr-defined]
        result = getattr(outcome, "result", None)
        return f"{text}\n{result}" if result else text

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a text file. Authorized by renker-core-authz before it runs."""
        return _format(tools.read_file(path))

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Write a text file. Requires human approval per the granted capability."""
        return _format(tools.write_file(path, content))

    @mcp.tool()
    def workspace_root() -> str:
        """Return the sandbox path the agent is scoped to (for orientation)."""
        return str(workspace)

    @mcp.tool()
    def audit_trail() -> str:
        """Return the tamper-evident audit trail of every decision so far."""
        audit.verify()
        lines = [
            f"{e.policy_decision:<17}{e.outcome:<10}{e.action} "
            f"{Path(e.target).name} #{e.entry_hash[:12]}"
            for e in audit.read_all()
        ]
        return "\n".join(lines) or "(no decisions yet)"

    return mcp


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()

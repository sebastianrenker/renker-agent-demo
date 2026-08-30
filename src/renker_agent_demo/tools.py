"""The tools an agent may call. Each one goes through the gateway first.

Nothing here trusts the caller. A tool turns a request into an
``(action, target, execute)`` triple and hands it to :class:`PolicyGateway`; the
side effect runs only if the policy engine allowed (or a human approved) it.
"""

from __future__ import annotations

from pathlib import Path

from renker_core_authz import Actor

from renker_agent_demo.gateway import PolicyGateway, ToolOutcome

# Dotted action verbs — these must match the capabilities granted in the store.
READ = "filesystem.read"
WRITE = "filesystem.write"
DELETE = "filesystem.delete"


class AgentTools:
    """A tool surface bound to one actor and one gateway."""

    def __init__(self, gateway: PolicyGateway, actor: Actor) -> None:
        self._gateway = gateway
        self._actor = actor

    def read_file(self, path: str) -> ToolOutcome:
        target = str(Path(path).expanduser())

        def _run() -> str:
            return Path(target).read_text(encoding="utf-8")

        return self._gateway.invoke(self._actor, READ, target, _run)

    def write_file(self, path: str, content: str) -> ToolOutcome:
        target = str(Path(path).expanduser())

        def _run() -> str:
            file = Path(target)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding="utf-8")
            return f"wrote {len(content)} chars to {file}"

        return self._gateway.invoke(self._actor, WRITE, target, _run)

    def delete_file(self, path: str) -> ToolOutcome:
        target = str(Path(path).expanduser())

        def _run() -> str:
            Path(target).unlink()
            return f"deleted {target}"

        return self._gateway.invoke(self._actor, DELETE, target, _run)

"""renker-agent-demo — securing an AI agent's tool calls with renker-core-authz.

The agent may *request* any action; the :class:`PolicyGateway` decides whether it
runs — outside the model, using only trusted capability grants — and records every
decision in a tamper-evident audit log.
"""

from __future__ import annotations

from renker_agent_demo.gateway import PolicyGateway, ToolOutcome
from renker_agent_demo.tools import AgentTools

__all__ = ["PolicyGateway", "ToolOutcome", "AgentTools"]

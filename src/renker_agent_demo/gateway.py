"""The policy gateway: every agent tool call is authorized before it runs.

This is the whole point of the demo. An LLM-driven agent decides *what to request*.
The gateway decides *what is allowed* — by calling ``renker_core_authz.evaluate``
against a trusted :class:`CapabilityStore`, never against the agent's own claims —
and writes every decision to a tamper-evident :class:`AuditLog`.

Prompt injection can change what the agent requests. It cannot change what the
capability store grants, so it cannot change the decision.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from renker_core_authz import Actor, CapabilityStore, Decision
from renker_core_authz.audit import AuditLog
from renker_core_authz.policy import PolicyResult, evaluate

#: Called only for REQUIRE_APPROVAL decisions. Return ``True`` to let the action run.
ApprovalHook = Callable[[PolicyResult], bool]

#: A tool's side effect. Executed only after the gateway authorizes the call.
Execute = Callable[[], str]


@dataclass(frozen=True)
class ToolOutcome:
    """Result of routing one tool call through the gateway."""

    decision: str
    reason: str
    executed: bool
    result: str | None = None


def _deny_all(_result: PolicyResult) -> bool:
    return False


class PolicyGateway:
    """Authorizes agent tool calls with renker-core-authz and audits every one."""

    def __init__(
        self,
        store: CapabilityStore,
        audit: AuditLog,
        approval_hook: ApprovalHook | None = None,
    ) -> None:
        self._store = store
        self._audit = audit
        self._approval: ApprovalHook = approval_hook or _deny_all

    def invoke(self, actor: Actor, action: str, target: str, execute: Execute) -> ToolOutcome:
        """Authorize ``action`` on ``target`` for ``actor``, then run it if permitted."""
        result = evaluate(actor=actor, action=action, target=target, store=self._store)

        if result.decision is Decision.DENY:
            self._record(result, outcome="blocked")
            return ToolOutcome("DENY", result.reason, executed=False)

        if result.decision is Decision.REQUIRE_APPROVAL:
            if not self._approval(result):
                self._record(result, outcome="declined")
                return ToolOutcome(
                    "REQUIRE_APPROVAL",
                    f"{result.reason} - declined by human",
                    executed=False,
                )
            value = execute()
            self._record(result, outcome="success")
            return ToolOutcome(
                "REQUIRE_APPROVAL",
                f"{result.reason} - approved by human",
                executed=True,
                result=value,
            )

        value = execute()
        self._record(result, outcome="success")
        return ToolOutcome("ALLOW", result.reason, executed=True, result=value)

    def _record(self, result: PolicyResult, outcome: str) -> None:
        self._audit.record(
            actor=result.actor,
            action=result.action,
            target=result.target,
            capability=result.capability_id,
            policy_decision=result.decision.value,
            reason=result.reason,
            outcome=outcome,
        )

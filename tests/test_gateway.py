"""Tests: the gateway makes the right decision and the audit chain holds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from renker_core_authz import Actor, Capability, CapabilityStore, PathScope
from renker_core_authz.audit import AuditError, AuditLog

from renker_agent_demo import AgentTools, PolicyGateway

AGENT = Actor("agent", "test")


def _make(tmp_path: Path, write_approval: str = "auto", approve: bool = False):
    now = datetime.now(UTC)
    later = now + timedelta(hours=1)
    ws = tmp_path / "workspace"
    (ws / "drafts").mkdir(parents=True)
    (tmp_path / "secrets").mkdir()
    (ws / "note.txt").write_text("hello", encoding="utf-8")

    store = CapabilityStore()
    for action, base, approval in [
        ("filesystem.read", ws, "auto"),
        ("filesystem.write", ws / "drafts", write_approval),
    ]:
        store.grant(
            Capability(
                capability=action,
                scope=PathScope(base=str(base)),
                granted_to=AGENT.urn,
                granted_by="human:owner",
                issued_at=now,
                expires_at=later,
                approval_policy=approval,
            )
        )
    audit = AuditLog(tmp_path / "audit.log")
    gateway = PolicyGateway(store, audit, approval_hook=lambda _r: approve)
    return AgentTools(gateway, AGENT), audit, ws, tmp_path


def test_allows_in_scope_read(tmp_path: Path) -> None:
    tools, _audit, ws, _root = _make(tmp_path)
    outcome = tools.read_file(ws / "note.txt")
    assert outcome.decision == "ALLOW"
    assert outcome.executed
    assert outcome.result == "hello"


def test_denies_out_of_scope_read(tmp_path: Path) -> None:
    tools, _audit, _ws, root = _make(tmp_path)
    outcome = tools.read_file(root / "secrets" / "api_key.txt")
    assert outcome.decision == "DENY"
    assert not outcome.executed


def test_denies_path_traversal_write(tmp_path: Path) -> None:
    tools, _audit, ws, _root = _make(tmp_path)
    outcome = tools.write_file(ws / "drafts" / ".." / ".." / "secrets" / "x.txt", "data")
    assert outcome.decision == "DENY"
    assert not outcome.executed
    assert not (tmp_path / "secrets" / "x.txt").exists()


def test_denies_ungranted_action(tmp_path: Path) -> None:
    tools, _audit, ws, _root = _make(tmp_path)
    outcome = tools.delete_file(ws / "drafts" / "note.txt")  # no delete capability granted
    assert outcome.decision == "DENY"
    assert not outcome.executed


def test_require_approval_declined_does_not_run(tmp_path: Path) -> None:
    tools, _audit, ws, _root = _make(tmp_path, write_approval="human", approve=False)
    outcome = tools.write_file(ws / "drafts" / "out.txt", "data")
    assert outcome.decision == "REQUIRE_APPROVAL"
    assert not outcome.executed
    assert not (ws / "drafts" / "out.txt").exists()


def test_require_approval_approved_runs(tmp_path: Path) -> None:
    tools, _audit, ws, _root = _make(tmp_path, write_approval="human", approve=True)
    outcome = tools.write_file(ws / "drafts" / "out.txt", "data")
    assert outcome.decision == "REQUIRE_APPROVAL"
    assert outcome.executed
    assert (ws / "drafts" / "out.txt").read_text(encoding="utf-8") == "data"


def test_audit_chain_verifies_and_detects_tampering(tmp_path: Path) -> None:
    tools, audit, ws, root = _make(tmp_path)
    tools.read_file(ws / "note.txt")
    tools.read_file(root / "secrets" / "nope.txt")
    audit.verify()  # intact

    log = tmp_path / "audit.log"
    text = log.read_text(encoding="utf-8").replace("blocked", "success", 1)
    log.write_text(text, encoding="utf-8")
    with pytest.raises(AuditError):
        audit.verify()

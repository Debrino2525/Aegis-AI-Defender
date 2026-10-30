"""Propose, dry-run, confirm, execute, sign, and roll back host response."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from aegis.response.audit import sign_audit, verify_audit
from aegis.response.executor import HostExecutor, preview_diff
from aegis.response.policy import (
    AUTO,
    CONSOLE_ASSET,
    OBSERVE,
    RECOMMEND,
    effective_mode,
    normalize_mode,
    site_ceiling,
)
from aegis.response.rules import RESPONSE_RULES, match_rules, rule_for_action
from aegis.response.store import ResponseStore, get_response_store, reset_response_store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(10)}"


def _normalize_ip(value: Any) -> str:
    return str(value or "").strip().lower().split("%", 1)[0]


class ResponseError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class ResponseEngine:
    def __init__(self, store: Optional[ResponseStore] = None, executor: Optional[HostExecutor] = None):
        self.store = store or get_response_store()
        self.executor = executor or HostExecutor()

    def site_policy(self) -> Dict[str, Any]:
        policy = self.store.site_policy()
        policy["default_asset_mode"] = RECOMMEND
        policy["ceiling"] = site_ceiling(policy["site_mode"], policy["auto_allowed"])
        policy["silent_auto"] = False
        return policy

    def set_site_policy(
        self,
        site_mode: str,
        auto_allowed: Optional[bool] = None,
        confirm_auto: bool = False,
    ) -> Dict[str, Any]:
        current = self.store.site_policy()
        mode = normalize_mode(site_mode, default=current["site_mode"])
        allowed = current["auto_allowed"] if auto_allowed is None else bool(auto_allowed)
        armed_at = current.get("auto_armed_at")
        if mode == AUTO and not allowed:
            raise ResponseError(
                "Auto is off on this site. New sites stay on Recommend until an operator enables Auto.",
                status_code=400,
            )
        if allowed and not current["auto_allowed"]:
            if not confirm_auto:
                raise ResponseError(
                    "Enabling Auto requires confirm_auto=true. This site will execute matching rules without a second click.",
                    status_code=400,
                )
            armed_at = _now()
        if not allowed:
            armed_at = None
            if mode == AUTO:
                mode = RECOMMEND
        self.store.save_site_policy(mode, allowed, auto_armed_at=armed_at)
        return self.site_policy()

    def asset_mode(self, asset_id: str) -> str:
        return self.store.asset_mode(asset_id or CONSOLE_ASSET)

    def effective_asset_mode(self, asset_id: str) -> str:
        site = self.store.site_policy()
        return effective_mode(self.asset_mode(asset_id), site["site_mode"], site["auto_allowed"])

    def set_asset_mode(self, asset_id: str, mode: str) -> Dict[str, Any]:
        asset_id = (asset_id or "").strip()
        if not asset_id:
            raise ResponseError("asset_id is required")
        requested = normalize_mode(mode)
        site = self.store.site_policy()
        if requested == AUTO and not site["auto_allowed"]:
            raise ResponseError(
                "Cannot set Auto on an asset while site Auto is off. New sites default to Recommend.",
                status_code=400,
            )
        saved = self.store.set_asset_mode(asset_id, requested)
        saved["effective_mode"] = self.effective_asset_mode(asset_id)
        saved["site_mode"] = site["site_mode"]
        saved["auto_allowed"] = site["auto_allowed"]
        return saved

    def list_rules(self) -> List[Dict[str, Any]]:
        return [dict(rule) for rule in RESPONSE_RULES]

    def resolve_asset(
        self,
        source_ip: Optional[str] = None,
        agent_id: Optional[str] = None,
        hosts: Optional[Sequence[Dict[str, Any]]] = None,
        console_ips: Optional[Iterable[str]] = None,
    ) -> Optional[str]:
        if agent_id:
            return agent_id
        ip = _normalize_ip(source_ip)
        for host in hosts or []:
            addrs = []
            for key in ("ipv4", "ipv6"):
                addrs.extend(host.get(key) or [])
            if host.get("remote_ip"):
                addrs.append(host.get("remote_ip"))
            if ip and ip in {_normalize_ip(a) for a in addrs if a}:
                return host.get("agent_id")
        local = {_normalize_ip(a) for a in (console_ips or []) if a}
        local.update({"127.0.0.1", "::1"})
        if ip and ip in local:
            return CONSOLE_ASSET
        if not ip:
            return CONSOLE_ASSET
        return None

    def annotate_incidents(
        self,
        incidents: Sequence[Dict[str, Any]],
        hosts: Optional[Sequence[Dict[str, Any]]] = None,
        console_ips: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        out = []
        for incident in incidents:
            row = dict(incident)
            asset_id = self.resolve_asset(
                source_ip=(incident.get("source_ips") or [None])[0] if incident.get("source_ips") else incident.get("source_ip"),
                hosts=hosts,
                console_ips=console_ips,
            )
            mode = self.effective_asset_mode(asset_id or CONSOLE_ASSET)
            proposals = match_rules({**incident, "asset_id": asset_id})
            row["response"] = {
                "asset_id": asset_id,
                "mode": mode if asset_id else RECOMMEND,
                "reachable": asset_id is not None,
                "proposals": proposals,
            }
            out.append(row)
        return out

    def preview(
        self,
        incident: Dict[str, Any],
        action: str,
        target: str,
        actor: str = "operator",
        agent_id: Optional[str] = None,
        hosts: Optional[Sequence[Dict[str, Any]]] = None,
        console_ips: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        action = (action or "").strip()
        target = (target or "").strip()
        if action == "resolve":
            raise ResponseError("resolve is not a host response action")
        source_ip = None
        if incident.get("source_ips"):
            source_ip = incident["source_ips"][0]
        elif incident.get("source_ip"):
            source_ip = incident["source_ip"]
        asset_id = self.resolve_asset(
            source_ip=source_ip,
            agent_id=agent_id or incident.get("asset_id"),
            hosts=hosts,
            console_ips=console_ips,
        )
        proposals = match_rules({**incident, "asset_id": asset_id}, action=action, target=target)
        if not proposals:
            # Operator-chosen action still needs a rule id and whatever evidence exists.
            rule = rule_for_action(action)
            evidence_ids = [
                str(a.get("id") or a.get("alert_id"))
                for a in (incident.get("alerts") or [])
                if a.get("id") or a.get("alert_id")
            ]
            if not evidence_ids or not rule:
                raise ResponseError(
                    "No evidence-linked rule matches that action. Containment was not applied.",
                    status_code=400,
                )
            if action != rule["action"] and action != rule.get("rollback_action"):
                raise ResponseError("Unsupported action type", status_code=400)
            proposal = {
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "action": action,
                "target": target,
                "rollback_action": rule.get("rollback_action"),
                "rollback_possible": bool(rule.get("rollback_possible")),
                "evidence": {
                    "alert_ids": evidence_ids,
                    "pattern_ids": sorted({str(a.get("pattern_id") or "") for a in (incident.get("alerts") or []) if a.get("pattern_id")}),
                    "incident_id": incident.get("id"),
                },
            }
        else:
            proposal = proposals[0]
            if target:
                proposal["target"] = target
            proposal["action"] = action

        mode = self.effective_asset_mode(asset_id or CONSOLE_ASSET)
        action_id = _new_id("act")
        diff = preview_diff(proposal["action"], proposal["target"], action_id=action_id)
        record = {
            "action_id": action_id,
            "status": "preview",
            "mode": mode,
            "actor": actor,
            "rule_id": proposal["rule_id"],
            "title": proposal.get("title"),
            "action": proposal["action"],
            "target": proposal["target"],
            "incident_id": incident.get("id"),
            "asset_id": asset_id,
            "reachable": asset_id is not None,
            "evidence": proposal.get("evidence") or {},
            "dry_run": diff,
            "confirmed": False,
            "applied": False,
            "rollback_possible": bool(proposal.get("rollback_possible")),
            "rollback_action": proposal.get("rollback_action"),
            "created_at": _now(),
        }
        record["audit"] = sign_audit(self._audit_payload(record, stage="preview"))
        return self.store.save_action(record)

    def confirm(self, action_id: str, actor: str = "operator", confirm: bool = True) -> Dict[str, Any]:
        record = self.store.get_action(action_id)
        if not record:
            raise ResponseError("Unknown action_id", status_code=404)
        if not confirm:
            raise ResponseError("confirm=true is required to leave preview", status_code=400)
        mode = self.effective_asset_mode(record.get("asset_id") or CONSOLE_ASSET)
        record["mode"] = mode
        if mode == OBSERVE:
            record["status"] = "observed"
            record["error"] = "Observe mode records the proposal and does not execute."
            record["audit"] = sign_audit(self._audit_payload(record, stage="observed"))
            return self.store.save_action(record)
        if actor == "auto" and mode != AUTO:
            raise ResponseError("Auto execution is not enabled for this asset", status_code=403)
        if not record.get("reachable") or not record.get("asset_id"):
            record["status"] = "failed"
            record["applied"] = False
            record["error"] = (
                "No enrolled agent for this host. Containment was not applied on the console box."
            )
            record["confirmed"] = True
            record["confirmed_by"] = actor
            record["confirmed_at"] = _now()
            record["audit"] = sign_audit(self._audit_payload(record, stage="failed"))
            return self.store.save_action(record)

        record["confirmed"] = True
        record["confirmed_by"] = actor
        record["confirmed_at"] = _now()
        asset_id = record["asset_id"]
        if asset_id == CONSOLE_ASSET:
            applied = self.executor.apply(
                record["action"],
                record["target"],
                action_id=record["action_id"],
                dry_run=False,
            )
            return self._finish_apply(record, applied, actor)

        command = {
            "command_id": _new_id("cmd"),
            "agent_id": asset_id,
            "action_id": record["action_id"],
            "kind": record["action"],
            "target": record["target"],
            "rule_id": record["rule_id"],
            "dry_run": False,
            "status": "queued",
        }
        self.store.enqueue_command(command)
        record["status"] = "queued"
        record["command_id"] = command["command_id"]
        record["message"] = f"Queued {record['action']} for agent {asset_id}. The agent applies it on the next heartbeat."
        record["audit"] = sign_audit(self._audit_payload(record, stage="queued"))
        return self.store.save_action(record)

    def rollback(self, action_id: str, actor: str = "operator", confirm: bool = True) -> Dict[str, Any]:
        original = self.store.get_action(action_id)
        if not original:
            raise ResponseError("Unknown action_id", status_code=404)
        if not confirm:
            raise ResponseError("confirm=true is required to roll back", status_code=400)
        if original.get("status") not in {"executed", "applied"} or not original.get("applied"):
            raise ResponseError("Only an applied action can be rolled back", status_code=400)
        if not original.get("rollback_possible") or not original.get("rollback_action"):
            raise ResponseError(
                "This action is not reversible (process kill and socket isolate cannot be undone).",
                status_code=400,
            )
        inverse = {
            "action_id": _new_id("act"),
            "status": "preview",
            "mode": original.get("mode"),
            "actor": actor,
            "rule_id": original.get("rule_id"),
            "title": f"Rollback {original.get('action')}",
            "action": original["rollback_action"],
            "target": original.get("target"),
            "incident_id": original.get("incident_id"),
            "asset_id": original.get("asset_id"),
            "reachable": original.get("reachable"),
            "evidence": original.get("evidence") or {},
            "parent_action_id": original["action_id"],
            "rollback_possible": True,
            "rollback_action": original.get("action"),
            "dry_run": preview_diff(original["rollback_action"], original.get("target") or "", action_id=original["action_id"]),
            "created_at": _now(),
        }
        inverse["audit"] = sign_audit(self._audit_payload(inverse, stage="preview"))
        saved = self.store.save_action(inverse)
        return self.confirm(saved["action_id"], actor=actor, confirm=True)

    def dequeue_commands(self, agent_id: str) -> List[Dict[str, Any]]:
        pending = self.store.pending_commands(agent_id)
        self.store.mark_commands_sent([row["command_id"] for row in pending])
        public = []
        for row in pending:
            public.append({
                "command_id": row["command_id"],
                "action_id": row["action_id"],
                "kind": row.get("kind"),
                "target": row.get("target"),
                "rule_id": row.get("rule_id"),
                "dry_run": False,
            })
            action = self.store.get_action(row["action_id"])
            if action and action.get("status") == "queued":
                action["status"] = "sent"
                action["audit"] = sign_audit(self._audit_payload(action, stage="sent"))
                self.store.save_action(action)
        return public

    def ingest_command_results(self, agent_id: str, results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        updated = []
        for raw in results or []:
            if not isinstance(raw, dict):
                continue
            command_id = raw.get("command_id")
            command = self.store.get_command(command_id) if command_id else None
            if not command or command.get("agent_id") != agent_id:
                continue
            action = self.store.get_action(command["action_id"])
            if not action:
                continue
            applied = bool(raw.get("applied"))
            action["applied"] = applied
            action["success"] = applied
            action["host_result"] = {
                "applied": applied,
                "message": raw.get("message"),
                "error": raw.get("error"),
                "platform": raw.get("platform"),
            }
            if applied:
                action["status"] = "executed"
                action["error"] = None
                action["message"] = raw.get("message") or f"Applied {action.get('action')} on agent {agent_id}."
            else:
                action["status"] = "failed"
                action["error"] = raw.get("error") or "Agent reported the change was not applied."
            command["status"] = "done"
            command["result"] = raw
            self.store.save_command(command)
            action["audit"] = sign_audit(self._audit_payload(action, stage=action["status"]))
            updated.append(self.store.save_action(action))
        return updated

    def tick_auto(
        self,
        incidents: Sequence[Dict[str, Any]],
        hosts: Optional[Sequence[Dict[str, Any]]] = None,
        console_ips: Optional[Iterable[str]] = None,
        actor: str = "auto",
    ) -> List[Dict[str, Any]]:
        fired = []
        for incident in incidents:
            if str(incident.get("status") or "").upper() in {"CONTAINED", "RESOLVED"}:
                continue
            source_ip = None
            if incident.get("source_ips"):
                source_ip = incident["source_ips"][0]
            asset_id = self.resolve_asset(
                source_ip=source_ip,
                hosts=hosts,
                console_ips=console_ips,
            )
            if not asset_id:
                continue
            if self.effective_asset_mode(asset_id) != AUTO:
                continue
            for proposal in match_rules({**incident, "asset_id": asset_id}):
                existing = self.store.find_open_action(
                    incident_id=str(incident.get("id") or ""),
                    rule_id=proposal["rule_id"],
                    action=proposal["action"],
                    target=proposal["target"],
                    asset_id=asset_id,
                )
                if existing:
                    continue
                previewed = self.preview(
                    incident,
                    proposal["action"],
                    proposal["target"],
                    actor=actor,
                    agent_id=asset_id,
                    hosts=hosts,
                    console_ips=console_ips,
                )
                fired.append(self.confirm(previewed["action_id"], actor=actor, confirm=True))
        return fired

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get_action(action_id)

    def list_actions(self, **kwargs: Any) -> List[Dict[str, Any]]:
        return self.store.list_actions(**kwargs)

    def verify_action_audit(self, action_id: str) -> Dict[str, Any]:
        record = self.store.get_action(action_id)
        if not record:
            raise ResponseError("Unknown action_id", status_code=404)
        audit = record.get("audit") or {}
        return {
            "action_id": action_id,
            "verified": verify_audit(audit),
            "audit": audit,
        }

    def _finish_apply(self, record: Dict[str, Any], applied: Dict[str, Any], actor: str) -> Dict[str, Any]:
        record["host_result"] = applied
        record["applied"] = bool(applied.get("applied"))
        record["success"] = bool(applied.get("applied"))
        if applied.get("applied"):
            record["status"] = "executed"
            record["message"] = applied.get("message") or f"Applied {record.get('action')} on this host."
            record["error"] = None
        else:
            record["status"] = "failed"
            record["error"] = applied.get("error") or "Host change was not applied."
        record["audit"] = sign_audit(self._audit_payload(record, stage=record["status"]))
        return self.store.save_action(record)

    def _audit_payload(self, record: Dict[str, Any], stage: str) -> Dict[str, Any]:
        evidence = record.get("evidence") or {}
        return {
            "action_id": record.get("action_id"),
            "rule_id": record.get("rule_id"),
            "action": record.get("action"),
            "target": record.get("target"),
            "asset_id": record.get("asset_id"),
            "incident_id": record.get("incident_id"),
            "mode": record.get("mode"),
            "actor": record.get("actor") or record.get("confirmed_by"),
            "stage": stage,
            "status": record.get("status"),
            "applied": bool(record.get("applied")),
            "evidence_alert_ids": list(evidence.get("alert_ids") or []),
            "dry_run_commands": list((record.get("dry_run") or {}).get("commands") or []),
            "timestamp": record.get("updated_at") or record.get("created_at") or _now(),
        }


_engine: Optional[ResponseEngine] = None


def get_response_engine() -> ResponseEngine:
    global _engine
    if _engine is None:
        _engine = ResponseEngine()
    return _engine


def reset_response_engine(clear: bool = True) -> None:
    global _engine
    reset_response_store(clear=clear)
    _engine = None

"""
Aegis AI — On-Call Management, Ownership Mapping & Escalation Timer.
Manages responder directories, asset ownership mappings, and dead-man escalation
timers when critical alerts remain unacknowledged.
"""

import time
import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from aegis.alerting.models import OnCallContact, AssetOwnerMapping, CriticalAlert


class EscalationManager:
    """Manages on-call routing, asset ownership resolution, and escalation progression."""

    def __init__(self, queue=None):
        self.queue = queue
        self.contacts: Dict[str, OnCallContact] = {}
        self.ownership_mappings: List[AssetOwnerMapping] = []
        self._load_or_seed()

    def _load_or_seed(self):
        """Loads contacts and mappings from SQLite if available, otherwise seeds defaults."""
        if self.queue:
            db_contacts = self.queue.list_contacts()
            db_mappings = self.queue.list_mappings()
            if db_contacts:
                for c in db_contacts:
                    self.contacts[c["contact_id"]] = OnCallContact(**c)
            if db_mappings:
                for m in db_mappings:
                    self.ownership_mappings.append(AssetOwnerMapping(**m))

        if not self.contacts:
            self._seed_default_contacts()

    def _seed_default_contacts(self):
        """Seeds default fallback contacts for initial setup."""
        c1 = OnCallContact(
            contact_id="ONCALL-PRIMARY",
            name="Primary SOC Responder",
            role="Tier-1 Security Analyst",
            phone="+233244000001",
            whatsapp_number="+233244000001",
            telegram_chat_id=""
        )
        c2 = OnCallContact(
            contact_id="ONCALL-LEAD",
            name="SOC Team Lead",
            role="Incident Commander",
            phone="+233201000002",
            whatsapp_number="+233201000002",
            telegram_chat_id=""
        )
        self.contacts[c1.contact_id] = c1
        self.contacts[c2.contact_id] = c2
        if self.queue:
            self.queue.save_contact(c1.model_dump())
            self.queue.save_contact(c2.model_dump())

        # Default fallback mapping
        m0 = AssetOwnerMapping(
            cidr_or_host="0.0.0.0/0",
            environment="Enterprise Network",
            owner_team="Security Operations",
            primary_contact_id=c1.contact_id,
            escalation_contact_id=c2.contact_id,
            escalation_timeout_mins=5
        )
        self.ownership_mappings.append(m0)
        if self.queue:
            self.queue.save_mapping(m0.model_dump())

    def add_contact(self, contact: OnCallContact):
        self.contacts[contact.contact_id] = contact
        if self.queue:
            self.queue.save_contact(contact.model_dump())

    def delete_contact(self, contact_id: str) -> bool:
        if contact_id in self.contacts:
            del self.contacts[contact_id]
        if self.queue:
            return self.queue.delete_contact(contact_id)
        return True

    def add_owner_mapping(self, mapping: AssetOwnerMapping):
        # Replace any previous rule for the same key so updates take effect immediately.
        self.ownership_mappings = [
            m for m in self.ownership_mappings if m.cidr_or_host != mapping.cidr_or_host
        ]
        self.ownership_mappings.append(mapping)
        if self.queue:
            self.queue.save_mapping(mapping.model_dump())

    def delete_mapping(self, cidr_or_host: str) -> bool:
        self.ownership_mappings = [m for m in self.ownership_mappings if m.cidr_or_host != cidr_or_host]
        if self.queue:
            return self.queue.delete_mapping(cidr_or_host)
        return True

    def _unassigned_contact(self) -> OnCallContact:
        return OnCallContact(
            contact_id="UNASSIGNED",
            name="Unassigned On-Call",
            role="Unconfigured",
            phone="",
        )

    def _contacts_for_mapping(self, mapping: AssetOwnerMapping) -> Tuple[OnCallContact, OnCallContact, str, int]:
        """Resolves responder contacts for a chosen ownership mapping."""
        if not self.contacts:
            unassigned = self._unassigned_contact()
            return unassigned, unassigned, mapping.environment, mapping.escalation_timeout_mins

        primary = self.contacts.get(mapping.primary_contact_id) or next(iter(self.contacts.values()))
        escalation = self.contacts.get(mapping.escalation_contact_id) or primary
        return primary, escalation, mapping.environment, mapping.escalation_timeout_mins

    def _fallback_mapping(self) -> Optional[AssetOwnerMapping]:
        """Default route used when no specific host or CIDR matches."""
        for cidr in ("0.0.0.0/0", "::/0", "*"):
            for mapping in self.ownership_mappings:
                if mapping.cidr_or_host == cidr:
                    return mapping
        if self.ownership_mappings:
            return self.ownership_mappings[-1]
        return None

    def resolve_contacts_for_target(self, target_ip_or_host: str) -> Tuple[OnCallContact, OnCallContact, str, int]:
        """
        Resolves primary responder, escalation contact, environment label, and timeout
        for a given asset IP address or hostname.

        CIDR rules use longest-prefix match. A default route (0.0.0.0/0) must not
        shadow a more specific subnet, regardless of list or database order.
        """
        target = (target_ip_or_host or "").strip()

        for mapping in self.ownership_mappings:
            if mapping.cidr_or_host == target:
                return self._contacts_for_mapping(mapping)

        best: Optional[AssetOwnerMapping] = None
        best_prefix = -1
        ip_obj = None
        if target:
            try:
                ip_obj = ipaddress.ip_address(target)
            except ValueError:
                ip_obj = None

        if ip_obj is not None:
            for mapping in self.ownership_mappings:
                if "/" not in mapping.cidr_or_host:
                    continue
                try:
                    net = ipaddress.ip_network(mapping.cidr_or_host, strict=False)
                except ValueError:
                    continue
                if ip_obj in net and net.prefixlen >= best_prefix:
                    best = mapping
                    best_prefix = net.prefixlen

        if best is not None:
            return self._contacts_for_mapping(best)

        fallback = self._fallback_mapping()
        if fallback is not None:
            return self._contacts_for_mapping(fallback)

        if not self.contacts:
            unassigned = self._unassigned_contact()
            return unassigned, unassigned, "Unassigned", 5

        contact = next(iter(self.contacts.values()))
        return contact, contact, "Unassigned", 5

    def check_escalation_needed(self, alert_dict: Dict) -> Tuple[bool, int, Optional[OnCallContact]]:
        """
        Checks if an unacknowledged alert has crossed its escalation threshold.
        Returns: (needs_escalation, target_escalation_level, contact_to_notify)
        """
        if alert_dict.get("acknowledged"):
            return False, 0, None

        created_at_str = alert_dict.get("created_at")
        if not created_at_str:
            return False, 0, None

        try:
            created_dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            elapsed_seconds = (now_dt - created_dt).total_seconds()
        except Exception:
            return False, 0, None

        current_level = alert_dict.get("escalation_level", 0)
        source_ip = alert_dict.get("source_ip", "")
        primary, lead, env, timeout_mins = self.resolve_contacts_for_target(source_ip)
        timeout_seconds = timeout_mins * 60

        # Level 0 -> Level 1 (At T+5 mins: escalate to Secondary/Lead)
        if current_level == 0 and elapsed_seconds >= timeout_seconds:
            return True, 1, lead

        # Level 1 -> Level 2 (At T+10 mins: escalate to Voice Call / Executive)
        if current_level == 1 and elapsed_seconds >= (timeout_seconds * 2):
            return True, 2, lead

        return False, current_level, None

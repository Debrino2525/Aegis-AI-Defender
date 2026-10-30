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

        self._drop_placeholder_directory()

    def _drop_placeholder_directory(self):
        """Remove the old sample on-call directory so it is not shown as staff."""
        placeholders = {
            "ONCALL-PRIMARY": "+233244000001",
            "ONCALL-LEAD": "+233201000002",
        }
        for contact_id, phone in placeholders.items():
            contact = self.contacts.get(contact_id)
            if contact and (contact.phone or "") == phone:
                self.delete_contact(contact_id)
        kept = []
        for mapping in self.ownership_mappings:
            is_sample = (
                mapping.cidr_or_host == "0.0.0.0/0"
                and mapping.environment == "Enterprise Network"
                and mapping.owner_team == "Security Operations"
                and mapping.primary_contact_id == "ONCALL-PRIMARY"
                and mapping.escalation_contact_id == "ONCALL-LEAD"
            )
            if is_sample:
                if self.queue:
                    self.queue.delete_mapping(mapping.cidr_or_host)
                continue
            kept.append(mapping)
        self.ownership_mappings = kept

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
        # Insert specific rules at front, generic 0.0.0.0/0 at back
        if mapping.cidr_or_host in ("0.0.0.0/0", "*"):
            self.ownership_mappings.append(mapping)
        else:
            self.ownership_mappings.insert(0, mapping)
        if self.queue:
            self.queue.save_mapping(mapping.model_dump())

    def delete_mapping(self, cidr_or_host: str) -> bool:
        self.ownership_mappings = [m for m in self.ownership_mappings if m.cidr_or_host != cidr_or_host]
        if self.queue:
            return self.queue.delete_mapping(cidr_or_host)
        return True

    def resolve_contacts_for_target(self, target_ip_or_host: str) -> Tuple[OnCallContact, OnCallContact, str, int]:
        """
        Resolves primary responder, escalation contact, environment label, and timeout
        for a given asset IP address or hostname.
        """
        if not self.ownership_mappings:
            return None, None, "Unassigned", 0

        def pair(mapping):
            primary = self.contacts.get(mapping.primary_contact_id)
            lead = self.contacts.get(mapping.escalation_contact_id) or primary
            return primary, lead, mapping.environment, mapping.escalation_timeout_mins

        # Try exact string match first
        for m in self.ownership_mappings:
            if m.cidr_or_host == target_ip_or_host:
                return pair(m)

        # Try CIDR network match
        try:
            ip_obj = ipaddress.ip_address(target_ip_or_host.strip())
            for m in self.ownership_mappings:
                if "/" in m.cidr_or_host:
                    net = ipaddress.ip_network(m.cidr_or_host, strict=False)
                    if ip_obj in net:
                        return pair(m)
        except ValueError:
            pass

        return pair(self.ownership_mappings[-1])

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
        if lead is None or not timeout_mins:
            return False, current_level, None
        timeout_seconds = timeout_mins * 60

        # Level 0 -> Level 1 (At T+5 mins: escalate to Secondary/Lead)
        if current_level == 0 and elapsed_seconds >= timeout_seconds:
            return True, 1, lead

        # Level 1 -> Level 2 (At T+10 mins: escalate to Voice Call / Executive)
        if current_level == 1 and elapsed_seconds >= (timeout_seconds * 2):
            return True, 2, lead

        return False, current_level, None

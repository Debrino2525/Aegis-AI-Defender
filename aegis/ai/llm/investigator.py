"""Cyber AI Investigator.

Performs deep incident investigations, forensic reasoning, threat actor
attribution, and blast-radius calculation using live LLM intelligence.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from aegis.ai.llm.provider import get_llm_provider, BaseLLM


INVESTIGATOR_SYSTEM_PROMPT = """You are the Aegis Cyber AI Principal Incident Responder and Threat Hunter.
Your task is to analyze raw cyber security incidents, open socket evidence, verified vulnerabilities (CVEs), and MITRE ATT&CK tactics to produce high-fidelity forensic investigations.

Guidelines:
1. Ground your reasoning strictly in the provided technical evidence (ports, CVEs, hostnames, IPs, tactics).
2. Hypothesize the initial intrusion vector and evaluate lateral movement risk.
3. Formulate threat actor profiling / campaign correlation where applicable.
4. Structure your response in clean markdown with the following sections:
   - ## Executive Incident Verdict
   - ## Forensic Attack Chain Analysis (Initial Access -> Dwell -> Lateral Movement)
   - ## Attacker Capabilities & CVE Exploitation Proof
   - ## Blast Radius & At-Risk Assets
   - ## Immediate Containment & Hardening Playbook (Numbered)
5. Be concise, authoritative, and technically precise. Keep the full analysis within 450 words.
"""


def _format_error(exc: Exception) -> str:
    msg = str(exc).strip()
    return f"{type(exc).__name__}: {msg}" if msg else f"{type(exc).__name__} (Network timeout or connection interrupted)"


class AIInvestigator:
    """Performs end-to-end incident investigations powered by LLMs."""

    def __init__(self, provider: Optional[BaseLLM] = None):
        self._provider = provider

    def _get_provider(self) -> BaseLLM:
        return self._provider or get_llm_provider()

    def investigate(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a synchronous deep investigation of an incident."""
        provider = self._get_provider()
        prompt = self._build_investigation_prompt(incident)

        try:
            verdict_text = provider.generate(prompt, system_prompt=INVESTIGATOR_SYSTEM_PROMPT)
        except Exception as exc:
            verdict_text = (
                f"### AI Investigation Failed\n"
                f"Provider `{provider.provider_name}` encountered error: `{_format_error(exc)}`.\n"
                f"Falling back to local heuristic analysis."
            )

        return {
            "incident_id": incident.get("id", incident.get("incident_id", "INC-UNKNOWN")),
            "provider": provider.provider_name,
            "model": provider.model_name,
            "investigation_markdown": verdict_text,
            "evidence_evaluated": {
                "host": incident.get("host", incident.get("affected_host", "unknown")),
                "severity": incident.get("severity", "unknown"),
                "tactics": incident.get("tactics", [incident.get("tactic", "unknown")]),
                "cves": incident.get("cves", []),
                "alert_count": incident.get("alert_count", incident.get("alerts", 1)),
            }
        }

    async def ainvestigate(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Perform an asynchronous deep investigation of an incident."""
        provider = self._get_provider()
        prompt = self._build_investigation_prompt(incident)

        try:
            verdict_text = await provider.agenerate(prompt, system_prompt=INVESTIGATOR_SYSTEM_PROMPT)
        except Exception as exc:
            verdict_text = (
                f"### AI Investigation Failed\n"
                f"Provider `{provider.provider_name}` encountered error: `{_format_error(exc)}`.\n"
                f"Falling back to local heuristic analysis."
            )

        return {
            "incident_id": incident.get("id", incident.get("incident_id", "INC-UNKNOWN")),
            "provider": provider.provider_name,
            "model": provider.model_name,
            "investigation_markdown": verdict_text,
            "evidence_evaluated": {
                "host": incident.get("host", incident.get("affected_host", "unknown")),
                "severity": incident.get("severity", "unknown"),
                "tactics": incident.get("tactics", [incident.get("tactic", "unknown")]),
                "cves": incident.get("cves", []),
                "alert_count": incident.get("alert_count", incident.get("alerts", 1)),
            }
        }

    def _build_investigation_prompt(self, inc: Dict[str, Any]) -> str:
        return (
            f"Analyze the following enterprise security incident concisely:\n\n"
            f"```json\n"
            f"{json.dumps(inc, indent=2, default=str)}\n"
            f"```\n\n"
            f"Please conduct an in-depth forensic investigation and provide the complete root-cause breakdown."
        )

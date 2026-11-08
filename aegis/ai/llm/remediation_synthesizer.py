"""AI Remediation Synthesizer.

Generates production-grade, operating-system-specific remediation scripts
(PowerShell, Bash, iptables, Palo Alto CLI, Fortinet CLI) for confirmed vulnerabilities.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from aegis.ai.llm.provider import get_llm_provider, BaseLLM


SYNTHESIZER_SYSTEM_PROMPT = """You are an automated Cyber Security Automation Engineer for Aegis AI Defender.
Your objective is to generate safe, hardened, syntax-checked remediation scripts to contain an active threat or patch a specific vulnerability.

Requirements:
1. Detect whether the target OS is Windows or Linux (default to multi-OS scripts if unstated).
2. Generate runnable, idempotent code blocks with appropriate rollback logic:
   - For Windows: Production PowerShell (`.ps1`) script (e.g., stopping malicious process, firewall isolation via `New-NetFirewallRule`, disabling vulnerable service, rotating passwords).
   - For Linux: Production Bash (`.sh`) script (e.g., `iptables`/`nftables` isolation, `systemctl stop`, unprivileged permission lockdowns).
   - For Network Firewalls: CLI commands for Palo Alto or Fortinet when applicable.
3. Include clear inline safety comments and dry-run switches where possible.
4. Output format: Clean markdown with fenced code blocks (```powershell and ```bash).
"""


class RemediationSynthesizer:
    """Generates real executable remediation and containment scripts."""

    def __init__(self, provider: Optional[BaseLLM] = None):
        self._provider = provider

    def _get_provider(self) -> BaseLLM:
        return self._provider or get_llm_provider()

    def synthesize(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation scripts for a vulnerability or compromised host."""
        provider = self._get_provider()
        prompt = (
            f"Generate an immediate incident remediation script for the following defect/incident:\n\n"
            f"```json\n"
            f"{json.dumps(finding, indent=2, default=str)}\n"
            f"```\n\n"
            f"Ensure the scripts provide both Windows PowerShell and Linux Bash containment procedures."
        )

        try:
            script_markdown = provider.generate(prompt, system_prompt=SYNTHESIZER_SYSTEM_PROMPT)
        except Exception as exc:
            script_markdown = (
                f"# Remediation Generation Failed via {provider.provider_name}: {exc}\n"
                f"# Fallback: Isolate host at network boundary immediately."
            )

        return {
            "target": finding.get("target", finding.get("host", "unknown")),
            "cve": finding.get("cve", finding.get("cves", "N/A")),
            "provider": provider.provider_name,
            "remediation_markdown": script_markdown,
        }

    async def asynthesize(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Asynchronously generate remediation scripts."""
        provider = self._get_provider()
        prompt = (
            f"Generate an immediate incident remediation script for the following defect/incident:\n\n"
            f"```json\n"
            f"{json.dumps(finding, indent=2, default=str)}\n"
            f"```\n\n"
            f"Ensure the scripts provide both Windows PowerShell and Linux Bash containment procedures."
        )

        try:
            script_markdown = await provider.agenerate(prompt, system_prompt=SYNTHESIZER_SYSTEM_PROMPT)
        except Exception as exc:
            script_markdown = (
                f"# Remediation Generation Failed via {provider.provider_name}: {exc}\n"
                f"# Fallback: Isolate host at network boundary immediately."
            )

        return {
            "target": finding.get("target", finding.get("host", "unknown")),
            "cve": finding.get("cve", finding.get("cves", "N/A")),
            "provider": provider.provider_name,
            "remediation_markdown": script_markdown,
        }

"""Pluggable LLM Provider Engine for Aegis AI Defender.

Supports:
- Google Gemini API (gemini-2.0-flash, gemini-1.5-pro, etc.)
- Local Ollama (air-gapped, zero-cloud via http://localhost:11434)
- OpenAI / OpenAI-compatible endpoints (vLLM, LM Studio, Azure OpenAI)
- Offline deterministic fallback when no LLM key or local server is present.
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """Configuration for LLM providers."""
    provider: str = Field(default="auto", description="gemini | ollama | openai | auto | fallback")
    api_key: Optional[str] = Field(default=None, description="API key for cloud provider")
    model_name: Optional[str] = Field(default=None, description="Model identifier")
    base_url: Optional[str] = Field(default=None, description="Base URL for Ollama or custom endpoint")
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    timeout_seconds: float = Field(default=180.0, ge=5.0, le=600.0)


class BaseLLM(ABC):
    """Abstract interface for LLM backends."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Synchronously generate text response."""

    @abstractmethod
    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Asynchronously generate text response."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is configured and reachable."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider label."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Active model name."""


# ---------------------------------------------------------------------------
# Google Gemini Provider
# ---------------------------------------------------------------------------

class GeminiLLM(BaseLLM):
    """Google Gemini API Provider using direct REST integration."""

    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, timeout: float = 60.0):
        self._api_key = (api_key or os.getenv("GEMINI_API_KEY", "")).strip()
        self._model = (model or os.getenv("GEMINI_MODEL", self.DEFAULT_MODEL)).strip()
        self._timeout = timeout

    @property
    def provider_name(self) -> str:
        return "Google Gemini API"

    @property
    def model_name(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return bool(self._api_key)

    def _build_payload(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}
        return payload

    def _endpoint(self) -> str:
        return f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent?key={self._api_key}"

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self._api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured.")
        payload = self._build_payload(prompt, system_prompt)
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(self._endpoint(), json=payload)
            resp.raise_for_status()
            data = resp.json()
            return self._extract_text(data)

    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self._api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured.")
        payload = self._build_payload(prompt, system_prompt)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(self._endpoint(), json=payload)
            resp.raise_for_status()
            data = resp.json()
            return self._extract_text(data)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts).strip()


# ---------------------------------------------------------------------------
# Local Ollama Provider (Air-Gapped & Local Privacy)
# ---------------------------------------------------------------------------

class OllamaLLM(BaseLLM):
    """Local Ollama Provider for offline air-gapped environments."""

    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "llama3.2"

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None, timeout: float = 180.0):
        self._base_url = (base_url or os.getenv("OLLAMA_BASE_URL", self.DEFAULT_BASE_URL)).rstrip("/")
        self._model = (model or os.getenv("OLLAMA_MODEL", self.DEFAULT_MODEL)).strip()
        self._timeout = timeout

    @property
    def provider_name(self) -> str:
        return "Local Ollama (Connected / Air-Gapped)"

    @property
    def model_name(self) -> str:
        return self._model

    def is_available(self) -> bool:
        try:
            with httpx.Client(timeout=3.0) as client:
                r = client.get(f"{self._base_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {"num_predict": 768, "temperature": 0.2},
        }
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(f"{self._base_url}/api/generate", json=payload)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()

    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {"num_predict": 768, "temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base_url}/api/generate", json=payload)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()


# ---------------------------------------------------------------------------
# OpenAI-Compatible Provider (OpenAI, vLLM, LM Studio)
# ---------------------------------------------------------------------------

class OpenAICompatibleLLM(BaseLLM):
    """OpenAI / vLLM / LocalAI Compatible Provider."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None, timeout: float = 60.0):
        self._api_key = (api_key or os.getenv("OPENAI_API_KEY", "")).strip()
        self._base_url = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self._model = (model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")).strip()
        self._timeout = timeout

    @property
    def provider_name(self) -> str:
        return f"OpenAI-Compatible ({self._base_url})"

    @property
    def model_name(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return bool(self._api_key or "localhost" in self._base_url or "127.0.0.1" in self._base_url)

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _payload(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return {"model": self._model, "messages": messages, "temperature": 0.2}

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(f"{self._base_url}/chat/completions", headers=self._headers(), json=self._payload(prompt, system_prompt))
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()

    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base_url}/chat/completions", headers=self._headers(), json=self._payload(prompt, system_prompt))
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()


# ---------------------------------------------------------------------------
# Offline Smart Fallback Provider
# ---------------------------------------------------------------------------

class SmartFallbackLLM(BaseLLM):
    """Deterministic fallback engine when no live LLM provider is connected."""

    @property
    def provider_name(self) -> str:
        return "Deterministic Heuristic Engine (Offline)"

    @property
    def model_name(self) -> str:
        return "aegis-builtin-expert-v1"

    def is_available(self) -> bool:
        return True

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        return (
            "[AEGIS AI - EXPERT FALLBACK]\n"
            "Notice: Cloud Gemini API or Local Ollama is not configured. "
            "To unlock real generative AI synthesis and deep forensic reasoning, configure GEMINI_API_KEY in .env or start Ollama locally.\n\n"
            "Summary: Automated heuristic triage completed. Host isolated to recommend status."
        )

    async def agenerate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        return self.generate(prompt, system_prompt)


# ---------------------------------------------------------------------------
# Global Engine Registry & Factory
# ---------------------------------------------------------------------------

_CURRENT_PROVIDER: Optional[BaseLLM] = None
_CURRENT_CONFIG: LLMConfig = LLMConfig()


def configure_llm(config: LLMConfig) -> BaseLLM:
    """Explicitly configure the active LLM provider."""
    global _CURRENT_PROVIDER, _CURRENT_CONFIG
    _CURRENT_CONFIG = config
    prov = config.provider.lower()

    timeout = max(config.timeout_seconds, 120.0) if prov == "ollama" else config.timeout_seconds

    if prov == "gemini":
        _CURRENT_PROVIDER = GeminiLLM(api_key=config.api_key, model=config.model_name, timeout=timeout)
    elif prov == "ollama":
        _CURRENT_PROVIDER = OllamaLLM(base_url=config.base_url, model=config.model_name, timeout=timeout)
    elif prov == "openai":
        _CURRENT_PROVIDER = OpenAICompatibleLLM(api_key=config.api_key, base_url=config.base_url, model=config.model_name, timeout=timeout)
    elif prov == "auto":
        _CURRENT_PROVIDER = auto_select_provider(config)
    else:
        _CURRENT_PROVIDER = SmartFallbackLLM()

    return _CURRENT_PROVIDER


def auto_select_provider(config: Optional[LLMConfig] = None) -> BaseLLM:
    """Automatically detect the best available LLM provider."""
    # 1. Check local Ollama first if running
    ollama = OllamaLLM(
        base_url=config.base_url if config else None,
        model=config.model_name if config else None,
        timeout=180.0,
    )
    if ollama.is_available():
        return ollama

    # 2. Check Gemini API
    api_key = (config.api_key if config else None) or os.getenv("GEMINI_API_KEY")
    if api_key:
        return GeminiLLM(api_key=api_key, model=config.model_name if config else None)

    # 3. Check OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        return OpenAICompatibleLLM(api_key=openai_key)

    return SmartFallbackLLM()


def get_llm_provider() -> BaseLLM:
    """Return the active LLM backend singleton."""
    global _CURRENT_PROVIDER
    if _CURRENT_PROVIDER is None:
        _CURRENT_PROVIDER = auto_select_provider(_CURRENT_CONFIG)
    return _CURRENT_PROVIDER

"""LLM backend abstraction.

Supports Ollama (default, fully local) and any OpenAI-compatible chat
endpoint. The agent loop talks only to `LLMClient.chat()`.
"""

from __future__ import annotations

import os

import requests


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, config: dict):
        lc = config.get("llm", {})
        self.backend = lc.get("backend", "ollama")
        self.base_url = lc.get("base_url", "http://localhost:11434").rstrip("/")
        self.model = lc.get("model", "llama3.1")
        self.api_key = os.environ.get(lc.get("api_key_env", "AEGIS_LLM_API_KEY"), "")
        self.timeout = int(lc.get("timeout", 180))

    def chat(self, messages: list[dict], *, json_mode: bool = False) -> str:
        if self.backend == "ollama":
            return self._ollama(messages, json_mode)
        return self._openai_compatible(messages, json_mode)

    def _ollama(self, messages, json_mode) -> str:
        payload = {"model": self.model, "messages": messages, "stream": False}
        if json_mode:
            payload["format"] = "json"
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload,
                              timeout=self.timeout)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except requests.RequestException as exc:
            raise LLMError(f"Ollama backend error: {exc}") from exc

    def _openai_compatible(self, messages, json_mode) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        payload = {"model": self.model, "messages": messages}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            r = requests.post(f"{self.base_url}/v1/chat/completions",
                              json=payload, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except requests.RequestException as exc:
            raise LLMError(f"OpenAI-compatible backend error: {exc}") from exc

    def available(self) -> bool:
        try:
            if self.backend == "ollama":
                return requests.get(f"{self.base_url}/api/tags", timeout=5).ok
            return True
        except requests.RequestException:
            return False

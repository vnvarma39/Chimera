from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from config import OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL


@dataclass
class LLMResult:
    text: str
    parsed: dict[str, Any] | None = None


class LLMClient:
    def __init__(self) -> None:
        self.enabled = bool(OPENAI_API_KEY)
        self.model = OPENAI_MODEL
        self.client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL) if self.enabled else None

    def complete(self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 400) -> LLMResult:
        if not self.enabled or self.client is None:
            return self._fallback(system, user, json_mode=json_mode)

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        resp = self.client.chat.completions.create(**kwargs)
        text = resp.choices[0].message.content or ""
        parsed = None
        if json_mode:
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
        return LLMResult(text=text, parsed=parsed)

    def _fallback(self, system: str, user: str, json_mode: bool = False) -> LLMResult:
        if json_mode:
            parsed = {
                "summary": "local fallback response",
                "system_hint": system[:120],
                "user_hint": user[:120],
            }
            return LLMResult(text=json.dumps(parsed), parsed=parsed)
        return LLMResult(text="local fallback response")


llm_client = LLMClient()

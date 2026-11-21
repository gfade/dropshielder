"""Shared Gemini SDK client builder (`v1beta` for Interactions + Decisions API)."""

from __future__ import annotations

import os
from typing import Any


def client() -> Any:
    from . import ProviderError

    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise ProviderError("GEMINI_API_KEY is not set")
    try:
        from google import genai
    except ImportError as exc:
        raise ProviderError("google-genai package is not installed") from exc
    return genai.Client(api_key=key, http_options={"api_version": "v1beta"})

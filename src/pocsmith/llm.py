"""LLM provider configuration for Claude Agent SDK calls."""
from __future__ import annotations

import os

from pocsmith.config import LlmConfig, PocsmithConfig


DEFAULT_MODEL = "claude-opus-4-7"
ABLITERATION_PROVIDER = "abliteration-ai"
ABLITERATION_MODEL = "abliterated-model"
ABLITERATION_BASE_URL = "https://api.abliteration.ai"


def default_llm_config() -> LlmConfig:
    return LlmConfig()


def effective_model(cfg: PocsmithConfig | None, override: str | None) -> str:
    if override:
        return override
    if cfg is not None:
        return cfg.llm.model
    return DEFAULT_MODEL


def sdk_env(llm: LlmConfig, *, model: str) -> dict[str, str]:
    """Build env overrides consumed by Claude Code through ClaudeAgentOptions."""
    env: dict[str, str] = {}

    if llm.provider == ABLITERATION_PROVIDER:
        env["ANTHROPIC_BASE_URL"] = llm.base_url or ABLITERATION_BASE_URL
        env["ANTHROPIC_CUSTOM_MODEL_OPTION"] = model
        env["ANTHROPIC_CUSTOM_MODEL_OPTION_NAME"] = model

    if llm.api_key_env != "ANTHROPIC_API_KEY":
        api_key = os.environ.get(llm.api_key_env)
        if api_key:
            env["ANTHROPIC_API_KEY"] = api_key

    return env


def effective_sdk_env(cfg: PocsmithConfig | None, *, model: str) -> dict[str, str]:
    llm = cfg.llm if cfg is not None else default_llm_config()
    return sdk_env(llm, model=model)

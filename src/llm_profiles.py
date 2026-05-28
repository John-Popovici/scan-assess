from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LLM_PROFILE_DIR = PROJECT_ROOT / "config" / "llm_profiles"


@dataclass(frozen=True)
class LlmProfile:
    name: str
    provider: str
    base_url: str
    model: str
    api_key: str | None
    api_key_env: str | None
    description: str
    context_size: int = 32768
    local_model_path: str | None = None
    local_server_binary: str = "llama-server"
    local_server_host: str = "127.0.0.1"
    local_server_port: int = 8033

    def resolved_api_key(self) -> str:
        if self.api_key is not None:
            return self.api_key
        if self.api_key_env:
            return os.environ.get(self.api_key_env, "")
        return ""


def _profile_path(name: str) -> Path:
    safe_name = name.strip().replace("/", "-")
    return LLM_PROFILE_DIR / f"{safe_name}.yaml"


def default_profile() -> LlmProfile:
    return LlmProfile(
        name="local-llamacpp",
        provider="openai-compatible-local",
        base_url="http://localhost:8033/v1",
        model="here",
        api_key="not-needed",
        api_key_env=None,
        description="Local llama.cpp OpenAI-compatible server.",
        context_size=32768,
        local_model_path=None,
        local_server_binary="llama-server",
        local_server_host="127.0.0.1",
        local_server_port=8033,
    )


def list_llm_profiles() -> list[str]:
    if not LLM_PROFILE_DIR.exists():
        return [default_profile().name]
    names = sorted(path.stem for path in LLM_PROFILE_DIR.glob("*.yaml"))
    return names or [default_profile().name]


def load_llm_profile(name: str | None) -> LlmProfile:
    profile_name = name or default_profile().name
    path = _profile_path(profile_name)
    if not path.exists():
        if profile_name == default_profile().name:
            return default_profile()
        raise FileNotFoundError(f"LLM profile not found: {profile_name}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return LlmProfile(
        name=str(raw.get("name") or profile_name),
        provider=str(raw.get("provider") or "openai-compatible"),
        base_url=str(raw.get("base_url") or default_profile().base_url),
        model=str(raw.get("model") or default_profile().model),
        api_key=raw.get("api_key"),
        api_key_env=raw.get("api_key_env"),
        description=str(raw.get("description") or ""),
        context_size=int(raw.get("context_size") or default_profile().context_size),
        local_model_path=raw.get("local_model_path"),
        local_server_binary=str(raw.get("local_server_binary") or default_profile().local_server_binary),
        local_server_host=str(raw.get("local_server_host") or default_profile().local_server_host),
        local_server_port=int(raw.get("local_server_port") or default_profile().local_server_port),
    )


def save_llm_profile(profile: LlmProfile) -> Path:
    LLM_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    path = _profile_path(profile.name)
    data: dict[str, Any] = {
        "name": profile.name,
        "provider": profile.provider,
        "base_url": profile.base_url,
        "model": profile.model,
        "api_key": profile.api_key,
        "api_key_env": profile.api_key_env,
        "description": profile.description,
        "context_size": profile.context_size,
        "local_model_path": profile.local_model_path,
        "local_server_binary": profile.local_server_binary,
        "local_server_host": profile.local_server_host,
        "local_server_port": profile.local_server_port,
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def delete_llm_profile(name: str) -> bool:
    if name == default_profile().name:
        return False
    path = _profile_path(name)
    if not path.exists():
        return False
    path.unlink()
    return True


def validate_llm_profile(profile: LlmProfile) -> list[str]:
    warnings: list[str] = []
    if not profile.base_url.strip():
        warnings.append("LLM profile has no base_url.")
    if not profile.model.strip():
        warnings.append("LLM profile has no model.")
    if profile.context_size < 1024:
        warnings.append("LLM context_size looks too small.")
    if profile.provider == "openai-compatible-local" and not profile.local_model_path:
        warnings.append("Local llama.cpp profile has no local_model_path, so the GUI cannot start it.")
    if profile.provider != "openai-compatible-local" and profile.api_key_env and not os.environ.get(profile.api_key_env):
        warnings.append(f"Environment variable {profile.api_key_env} is not currently set.")
    if not profile.api_key and not profile.api_key_env:
        warnings.append("LLM profile has no api_key or api_key_env; this only works for unauthenticated local servers.")
    return warnings

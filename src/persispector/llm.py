"""Shared OpenAI-compatible structured-output helpers."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, TypeVar

from langchain.globals import set_llm_cache
from langchain_community.cache import SQLiteCache
from langchain_openai import ChatOpenAI
from pydantic import BaseModel


logger = logging.getLogger(__name__)
ModelT = TypeVar("ModelT", bound=BaseModel)


def configure_llm_cache() -> None:
    """Configure the process-wide LangChain cache from project settings."""

    enabled = os.getenv("ENABLE_LLM_CACHE", "true").lower() in {
        "true", "1", "yes"
    }
    if not enabled:
        return
    cache_dir = Path(os.getenv("LLM_CACHE_DIR", ".llm_cache"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    set_llm_cache(SQLiteCache(database_path=str(cache_dir / "langchain.db")))


def chat_model(model_name: str, temperature: float) -> ChatOpenAI:
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise ValueError("API_KEY is not set.")
    return ChatOpenAI(
        base_url=os.getenv("BASE_URL", "https://openrouter.ai/api/v1"),
        api_key=api_key,  # type: ignore[arg-type]
        model=model_name,
        temperature=temperature,
    )


def environment_model(model_env: str, default: str = "openai/gpt-4o") -> str:
    return os.getenv(model_env) or os.getenv("LLM_MODEL") or default


def invoke_structured_with_retries(
    chain: Any,
    variables: dict[str, str],
    result_type: type[ModelT],
    *,
    operation: str = "Model extraction",
    validate: Callable[[ModelT], None] | None = None,
    log: logging.Logger | None = None,
) -> ModelT:
    """Invoke a structured chain and validate its result with bounded retries."""

    attempts = max(1, int(os.getenv("LLM_PARSE_RETRIES", "3")))
    last_error: Exception | None = None
    event_logger = log or logger
    for attempt in range(1, attempts + 1):
        try:
            result = result_type.model_validate(chain.invoke(variables))
            if validate is not None:
                validate(result)
            return result
        except Exception as error:
            last_error = error
            if attempt < attempts:
                event_logger.warning(
                    "%s attempt %d/%d failed; retrying (error_type=%s)",
                    operation,
                    attempt,
                    attempts,
                    type(error).__name__,
                )
            else:
                event_logger.error(
                    "%s failed after %d attempt(s) (error_type=%s)",
                    operation,
                    attempts,
                    type(error).__name__,
                )
    assert last_error is not None
    raise last_error

"""OpenAI-compatible structured-output provider, following Atlas conventions."""

from __future__ import annotations

import logging
from typing import Protocol

from langchain_core.prompts import ChatPromptTemplate

from persispector.empirical.models import EvidenceBundle, IPDAssessment
from persispector.empirical.prompts import (
    HUMAN_PROMPT,
    SYSTEM_PROMPT,
    assessment_variables,
)
from persispector.llm import (
    chat_model,
    configure_llm_cache,
    environment_model,
    invoke_structured_with_retries,
)


logger = logging.getLogger(__name__)


class AssessmentClient(Protocol):
    model_name: str

    def assess(self, bundle: EvidenceBundle) -> IPDAssessment: ...


class OpenAICompatibleAssessmentClient:
    """Structured-output client configured by Atlas-compatible environment variables."""

    def __init__(
        self,
        *,
        model_env: str = "IPD_STUDY_MODEL",
        temperature: float = 0.1,
    ):
        self.model_name = environment_model(model_env)
        configure_llm_cache()
        self._llm = chat_model(self.model_name, temperature).with_structured_output(
            IPDAssessment
        )
        self._prompt = ChatPromptTemplate.from_messages(
            [("system", SYSTEM_PROMPT), ("human", HUMAN_PROMPT)]
        )

    def assess(self, bundle: EvidenceBundle) -> IPDAssessment:
        return invoke_structured_with_retries(
            self._prompt | self._llm,
            assessment_variables(bundle),
            IPDAssessment,
            operation="Model assessment",
            log=logger,
        )

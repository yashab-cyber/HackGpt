"""Model registry and provider abstraction layer for HackGPT.

Provides a centralized catalog of supported AI models across multiple
providers, along with helper functions for querying model metadata,
filtering by provider, and discovering available providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

__all__ = [
    "ModelProvider",
    "ModelInfo",
    "MODEL_CATALOG",
    "get_models_by_provider",
    "get_model_info",
    "list_all_models",
    "get_available_providers",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ModelProvider(Enum):
    """Supported AI model providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    LOCAL = "local"
    OPENROUTER = "openrouter"
    GLM = "glm"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ModelInfo:
    """Metadata for a single AI model.

    Attributes:
        model_id: The canonical identifier used when calling the provider API
            (e.g. ``'gpt-5'``, ``'claude-sonnet-4-20250514'``).
        provider: The :class:`ModelProvider` that hosts this model.
        display_name: A human-friendly label for UI rendering.
        max_tokens: Maximum number of *output* tokens the model can generate
            in a single completion.
        supports_streaming: Whether the model supports streaming responses.
        supports_tools: Whether the model supports tool / function calling.
        context_window: Total context window size (input + output) in tokens.
        description: Optional free-text description of the model.
    """

    model_id: str
    provider: ModelProvider
    display_name: str
    max_tokens: int
    supports_streaming: bool = True
    supports_tools: bool = False
    context_window: int = 128_000
    description: str = ""


# ---------------------------------------------------------------------------
# Model catalog
# ---------------------------------------------------------------------------

MODEL_CATALOG: Dict[str, ModelInfo] = {
    # ----- OpenAI --------------------------------------------------------
    "gpt-5": ModelInfo(
        model_id="gpt-5",
        provider=ModelProvider.OPENAI,
        display_name="GPT-5",
        max_tokens=16_384,
        supports_tools=True,
        context_window=200_000,
        description="OpenAI's most capable general-purpose model.",
    ),
    "gpt-5.6": ModelInfo(
        model_id="gpt-5.6",
        provider=ModelProvider.OPENAI,
        display_name="GPT-5.6",
        max_tokens=16_384,
        supports_tools=True,
        context_window=200_000,
        description="Incremental improvement over GPT-5 with enhanced reasoning.",
    ),
    "gpt-4o": ModelInfo(
        model_id="gpt-4o",
        provider=ModelProvider.OPENAI,
        display_name="GPT-4o",
        max_tokens=4_096,
        supports_tools=True,
        context_window=128_000,
        description="OpenAI's optimized multimodal model.",
    ),
    "gpt-4o-mini": ModelInfo(
        model_id="gpt-4o-mini",
        provider=ModelProvider.OPENAI,
        display_name="GPT-4o Mini",
        max_tokens=4_096,
        supports_tools=True,
        context_window=128_000,
        description="Lightweight variant of GPT-4o optimized for speed and cost.",
    ),
    "o3": ModelInfo(
        model_id="o3",
        provider=ModelProvider.OPENAI,
        display_name="o3",
        max_tokens=100_000,
        supports_tools=True,
        context_window=200_000,
        description="OpenAI reasoning model with extended output capacity.",
    ),
    "o4-mini": ModelInfo(
        model_id="o4-mini",
        provider=ModelProvider.OPENAI,
        display_name="o4-mini",
        max_tokens=65_536,
        supports_tools=True,
        context_window=200_000,
        description="Compact reasoning model balancing capability and efficiency.",
    ),

    # ----- Anthropic -----------------------------------------------------
    "claude-sonnet-5": ModelInfo(
        model_id="claude-sonnet-4-20250514",
        provider=ModelProvider.ANTHROPIC,
        display_name="Claude Sonnet 5",
        max_tokens=16_384,
        supports_tools=True,
        context_window=200_000,
        description="Anthropic's high-performance model with strong coding ability.",
    ),
    "claude-opus-4.8": ModelInfo(
        model_id="claude-opus-4-20250918",
        provider=ModelProvider.ANTHROPIC,
        display_name="Claude Opus 4.8",
        max_tokens=16_384,
        supports_tools=True,
        context_window=200_000,
        description="Anthropic's most powerful model for complex analysis.",
    ),
    "claude-haiku-3.5": ModelInfo(
        model_id="claude-3-5-haiku-20241022",
        provider=ModelProvider.ANTHROPIC,
        display_name="Claude Haiku 3.5",
        max_tokens=8_192,
        supports_tools=True,
        context_window=200_000,
        description="Fast and affordable Anthropic model for lightweight tasks.",
    ),

    # ----- Google Gemini -------------------------------------------------
    "gemini-3.5-flash": ModelInfo(
        model_id="gemini-3.5-flash",
        provider=ModelProvider.GOOGLE,
        display_name="Gemini 3.5 Flash",
        max_tokens=8_192,
        context_window=1_000_000,
        description="Ultra-fast Google model optimized for low-latency workloads.",
    ),
    "gemini-3.1-pro": ModelInfo(
        model_id="gemini-3.1-pro",
        provider=ModelProvider.GOOGLE,
        display_name="Gemini 3.1 Pro",
        max_tokens=8_192,
        context_window=2_000_000,
        description="Google's professional-grade model with a 2M token context.",
    ),
    "gemini-2.5-pro": ModelInfo(
        model_id="gemini-2.5-pro",
        provider=ModelProvider.GOOGLE,
        display_name="Gemini 2.5 Pro",
        max_tokens=65_536,
        context_window=1_000_000,
        description="Google's advanced reasoning model with extended output.",
    ),
    "gemini-2.5-flash": ModelInfo(
        model_id="gemini-2.5-flash",
        provider=ModelProvider.GOOGLE,
        display_name="Gemini 2.5 Flash",
        max_tokens=65_536,
        context_window=1_000_000,
        description="Fast Google model combining speed with large output capacity.",
    ),

    # ----- DeepSeek ------------------------------------------------------
    "deepseek-r1": ModelInfo(
        model_id="deepseek-r1",
        provider=ModelProvider.DEEPSEEK,
        display_name="DeepSeek R1",
        max_tokens=8_192,
        context_window=128_000,
        description="DeepSeek reasoning model with chain-of-thought capability.",
    ),
    "deepseek-v3": ModelInfo(
        model_id="deepseek-chat",
        provider=ModelProvider.DEEPSEEK,
        display_name="DeepSeek V3",
        max_tokens=8_192,
        context_window=128_000,
        description="DeepSeek's general-purpose conversational model.",
    ),

    # ----- GLM -----------------------------------------------------------
    "glm-5.2": ModelInfo(
        model_id="glm-5.2",
        provider=ModelProvider.GLM,
        display_name="GLM 5.2",
        max_tokens=4_096,
        context_window=128_000,
        description="Zhipu AI's latest bilingual large language model.",
    ),
    "glm-4-plus": ModelInfo(
        model_id="glm-4-plus",
        provider=ModelProvider.GLM,
        display_name="GLM-4 Plus",
        max_tokens=4_096,
        context_window=128_000,
        description="Enhanced variant of GLM-4 with improved instruction following.",
    ),

    # ----- Local LLMs (Ollama) -------------------------------------------
    "llama3.3:70b": ModelInfo(
        model_id="llama3.3:70b",
        provider=ModelProvider.LOCAL,
        display_name="LLaMA 3.3 70B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Meta's 70B parameter LLaMA model running locally via Ollama.",
    ),
    "llama3.2:3b": ModelInfo(
        model_id="llama3.2:3b",
        provider=ModelProvider.LOCAL,
        display_name="LLaMA 3.2 3B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Lightweight 3B LLaMA model for resource-constrained environments.",
    ),
    "mistral:7b": ModelInfo(
        model_id="mistral:7b",
        provider=ModelProvider.LOCAL,
        display_name="Mistral 7B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Mistral AI's efficient 7B parameter model via Ollama.",
    ),
    "codellama:13b": ModelInfo(
        model_id="codellama:13b",
        provider=ModelProvider.LOCAL,
        display_name="Code LLaMA 13B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Meta's code-specialized 13B model for programming tasks.",
    ),
    "qwen2.5:32b": ModelInfo(
        model_id="qwen2.5:32b",
        provider=ModelProvider.LOCAL,
        display_name="Qwen 2.5 32B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Alibaba's 32B parameter Qwen model via Ollama.",
    ),
    "deepseek-r1:14b": ModelInfo(
        model_id="deepseek-r1:14b",
        provider=ModelProvider.LOCAL,
        display_name="DeepSeek R1 14B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Local 14B distillation of the DeepSeek R1 reasoning model.",
    ),
    "phi-4:14b": ModelInfo(
        model_id="phi-4:14b",
        provider=ModelProvider.LOCAL,
        display_name="Phi-4 14B",
        max_tokens=4_096,
        supports_streaming=False,
        context_window=128_000,
        description="Microsoft's compact yet capable Phi-4 model via Ollama.",
    ),

    # ----- OpenRouter ----------------------------------------------------
    "openrouter/auto": ModelInfo(
        model_id="openrouter/auto",
        provider=ModelProvider.OPENROUTER,
        display_name="OpenRouter Auto",
        max_tokens=4_096,
        context_window=128_000,
        description="Automatic model routing via the OpenRouter aggregator.",
    ),
}


# ---------------------------------------------------------------------------
# Provider metadata (for discovery / UI)
# ---------------------------------------------------------------------------

_PROVIDER_META: Dict[ModelProvider, Dict[str, Any]] = {
    ModelProvider.OPENAI: {
        "name": "OpenAI",
        "description": "GPT and o-series models from OpenAI.",
        "required_env_vars": ["OPENAI_API_KEY"],
    },
    ModelProvider.ANTHROPIC: {
        "name": "Anthropic",
        "description": "Claude family of models from Anthropic.",
        "required_env_vars": ["ANTHROPIC_API_KEY"],
    },
    ModelProvider.GOOGLE: {
        "name": "Google",
        "description": "Gemini models from Google DeepMind.",
        "required_env_vars": ["GOOGLE_API_KEY"],
    },
    ModelProvider.DEEPSEEK: {
        "name": "DeepSeek",
        "description": "Reasoning and chat models from DeepSeek.",
        "required_env_vars": ["DEEPSEEK_API_KEY"],
    },
    ModelProvider.LOCAL: {
        "name": "Local (Ollama)",
        "description": "Locally-hosted models served via Ollama.",
        "required_env_vars": [],
    },
    ModelProvider.OPENROUTER: {
        "name": "OpenRouter",
        "description": "Multi-provider model aggregator with automatic routing.",
        "required_env_vars": ["OPENROUTER_API_KEY"],
    },
    ModelProvider.GLM: {
        "name": "GLM (Zhipu AI)",
        "description": "GLM series models from Zhipu AI.",
        "required_env_vars": ["GLM_API_KEY"],
    },
}


# ---------------------------------------------------------------------------
# Public query helpers
# ---------------------------------------------------------------------------

def get_models_by_provider(provider: ModelProvider) -> List[ModelInfo]:
    """Return all registered models that belong to *provider*.

    Args:
        provider: The :class:`ModelProvider` to filter by.

    Returns:
        A list of :class:`ModelInfo` instances for the given provider,
        sorted alphabetically by ``model_id``.
    """
    return sorted(
        [m for m in MODEL_CATALOG.values() if m.provider is provider],
        key=lambda m: m.model_id,
    )


def get_model_info(model_id: str) -> Optional[ModelInfo]:
    """Look up a single model by its catalog key.

    Args:
        model_id: The key used in :data:`MODEL_CATALOG` (e.g. ``'gpt-5'``,
            ``'claude-sonnet-5'``).

    Returns:
        The corresponding :class:`ModelInfo`, or ``None`` if not found.
    """
    return MODEL_CATALOG.get(model_id)


def list_all_models() -> List[ModelInfo]:
    """Return every model in the catalog.

    Returns:
        A list of all :class:`ModelInfo` instances, sorted alphabetically
        by ``model_id``.
    """
    return sorted(MODEL_CATALOG.values(), key=lambda m: m.model_id)


def get_available_providers() -> List[Dict[str, Any]]:
    """Return metadata for every supported provider.

    Each entry contains:
        - **name** (*str*): Human-readable provider name.
        - **description** (*str*): Short description of the provider.
        - **required_env_vars** (*List[str]*): Environment variables needed.
        - **model_count** (*int*): Number of models registered for this
          provider.

    Returns:
        A list of provider-info dictionaries, one per
        :class:`ModelProvider` member.
    """
    providers: List[Dict[str, Any]] = []
    for member in ModelProvider:
        meta = _PROVIDER_META[member]
        providers.append(
            {
                "name": meta["name"],
                "description": meta["description"],
                "required_env_vars": meta["required_env_vars"],
                "model_count": len(get_models_by_provider(member)),
            }
        )
    return providers

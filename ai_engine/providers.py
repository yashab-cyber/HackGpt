#!/usr/bin/env python3
"""
Provider client implementations for HackGPT multi-model AI support.

Implements a unified interface to call different AI providers through a
common abstract base class. Supports OpenAI, Anthropic, Google Gemini,
DeepSeek, GLM (Zhipu), Ollama (local), and OpenRouter.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

# Third-party imports — wrapped so the module loads even when
# optional dependencies are missing.
try:
    import openai
    _HAS_OPENAI = True
except ImportError:
    openai = None  # type: ignore[assignment]
    _HAS_OPENAI = False

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    requests = None  # type: ignore[assignment]
    _HAS_REQUESTS = False

from .model_registry import ModelProvider, ModelInfo, MODEL_CATALOG, get_model_info

logger = logging.getLogger(__name__)

__all__ = [
    "BaseProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GoogleProvider",
    "DeepSeekProvider",
    "GLMProvider",
    "OllamaProvider",
    "OpenRouterProvider",
    "ProviderFactory",
]


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class BaseProvider(ABC):
    """Abstract base class for all AI provider clients.

    Parameters:
        api_key:  Authentication key for the provider API.
        base_url: Optional override for the provider's API endpoint.
    """

    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key
        self.base_url = base_url

    @abstractmethod
    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Send a chat-completion request and return the assistant's text.

        Args:
            model_id:    Provider-specific model identifier.
            messages:    Conversation history as a list of role/content dicts.
            max_tokens:  Maximum number of tokens in the response.
            temperature: Sampling temperature.

        Returns:
            The assistant's response text.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when the provider is ready to serve requests."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable name of this provider."""


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

class OpenAIProvider(BaseProvider):
    """Provider client for the OpenAI API (GPT family).

    Falls back to the ``OPENAI_API_KEY`` environment variable when no
    *api_key* is supplied explicitly.
    """

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("OPENAI_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url)
        self._client: Optional[object] = None

    def _get_client(self) -> "openai.OpenAI":
        """Lazily create and cache the OpenAI client."""
        if self._client is None:
            if not _HAS_OPENAI:
                raise ImportError(
                    "The 'openai' package is required for OpenAIProvider. "
                    "Install it with: pip install openai"
                )
            kwargs: Dict = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = openai.OpenAI(**kwargs)
        return self._client  # type: ignore[return-value]

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call OpenAI chat completions endpoint."""
        client = self._get_client()
        try:
            response = client.chat.completions.create(
                model=model_id,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as exc:
            logger.error("OpenAI chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        """Available when an API key is configured."""
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "OpenAI"


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class AnthropicProvider(BaseProvider):
    """Provider client for the Anthropic Messages API (Claude family).

    Uses raw HTTP via *requests* rather than a vendor SDK.
    Falls back to the ``ANTHROPIC_API_KEY`` environment variable.
    """

    _DEFAULT_BASE_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url or self._DEFAULT_BASE_URL)

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call the Anthropic Messages API."""
        if not _HAS_REQUESTS:
            raise ImportError(
                "The 'requests' package is required for AnthropicProvider. "
                "Install it with: pip install requests"
            )
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model_id,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        try:
            resp = requests.post(self.base_url, headers=headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]
        except Exception as exc:
            logger.error("Anthropic chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "Anthropic"


# ---------------------------------------------------------------------------
# Google (Gemini / Generative Language API)
# ---------------------------------------------------------------------------

class GoogleProvider(BaseProvider):
    """Provider client for Google Generative Language API (Gemini family).

    Falls back to the ``GOOGLE_API_KEY`` environment variable.
    """

    _DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("GOOGLE_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url or self._DEFAULT_BASE_URL)

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call the Google generateContent endpoint."""
        if not _HAS_REQUESTS:
            raise ImportError(
                "The 'requests' package is required for GoogleProvider. "
                "Install it with: pip install requests"
            )
        url = (
            f"{self.base_url}/models/{model_id}:generateContent"
            f"?key={self.api_key}"
        )
        # Flatten messages into a single prompt text for the REST API.
        combined_text = "\n".join(
            f"{msg.get('role', 'user')}: {msg.get('content', '')}"
            for msg in messages
        )
        payload = {
            "contents": [{"parts": [{"text": combined_text}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }
        try:
            resp = requests.post(url, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:
            logger.error("Google chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "Google"


# ---------------------------------------------------------------------------
# DeepSeek (OpenAI-compatible)
# ---------------------------------------------------------------------------

class DeepSeekProvider(BaseProvider):
    """Provider client for the DeepSeek API (OpenAI-compatible).

    Falls back to the ``DEEPSEEK_API_KEY`` environment variable.
    """

    _DEFAULT_BASE_URL = "https://api.deepseek.com/v1"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url or self._DEFAULT_BASE_URL)
        self._client: Optional[object] = None

    def _get_client(self) -> "openai.OpenAI":
        """Lazily create and cache the OpenAI-compatible client."""
        if self._client is None:
            if not _HAS_OPENAI:
                raise ImportError(
                    "The 'openai' package is required for DeepSeekProvider. "
                    "Install it with: pip install openai"
                )
            self._client = openai.OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        return self._client  # type: ignore[return-value]

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call DeepSeek chat completions via the OpenAI-compatible API."""
        client = self._get_client()
        try:
            response = client.chat.completions.create(
                model=model_id,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as exc:
            logger.error("DeepSeek chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "DeepSeek"


# ---------------------------------------------------------------------------
# GLM / Zhipu (BigModel)
# ---------------------------------------------------------------------------

class GLMProvider(BaseProvider):
    """Provider client for the GLM / Zhipu BigModel API.

    Uses an OpenAI-compatible request/response format over raw HTTP.
    Falls back to ``GLM_API_KEY`` or ``ZHIPU_API_KEY`` environment variables.
    """

    _DEFAULT_BASE_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("GLM_API_KEY") or os.getenv("ZHIPU_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url or self._DEFAULT_BASE_URL)

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call the GLM chat completions endpoint."""
        if not _HAS_REQUESTS:
            raise ImportError(
                "The 'requests' package is required for GLMProvider. "
                "Install it with: pip install requests"
            )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            resp = requests.post(self.base_url, headers=headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.error("GLM chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "GLM"


# ---------------------------------------------------------------------------
# Ollama (local LLM)
# ---------------------------------------------------------------------------

class OllamaProvider(BaseProvider):
    """Provider client for locally-running Ollama instances.

    Defaults to ``http://localhost:11434`` but honours the
    ``LOCAL_LLM_ENDPOINT`` environment variable.
    """

    _DEFAULT_BASE_URL = "http://localhost:11434"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_url = base_url or os.getenv("LOCAL_LLM_ENDPOINT", self._DEFAULT_BASE_URL)
        # Ollama does not require an API key.
        super().__init__(api_key=api_key, base_url=resolved_url)

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call the Ollama ``/api/chat`` endpoint."""
        if not _HAS_REQUESTS:
            raise ImportError(
                "The 'requests' package is required for OllamaProvider. "
                "Install it with: pip install requests"
            )
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model_id,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        try:
            resp = requests.post(url, json=payload, timeout=300)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
        except Exception as exc:
            logger.error("Ollama chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        """Check connectivity by hitting the ``/api/tags`` endpoint."""
        if not _HAS_REQUESTS:
            return False
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags", timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "Ollama"


# ---------------------------------------------------------------------------
# OpenRouter (OpenAI-compatible aggregator)
# ---------------------------------------------------------------------------

class OpenRouterProvider(BaseProvider):
    """Provider client for the OpenRouter API (OpenAI-compatible).

    Sends additional ``HTTP-Referer`` and ``X-Title`` headers required by
    the OpenRouter terms of service.  Falls back to the
    ``OPENROUTER_API_KEY`` environment variable.
    """

    _DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self, api_key: str = None, base_url: str = None):
        resolved_key = api_key or os.getenv("OPENROUTER_API_KEY")
        super().__init__(api_key=resolved_key, base_url=base_url or self._DEFAULT_BASE_URL)
        self._client: Optional[object] = None

    def _get_client(self) -> "openai.OpenAI":
        """Lazily create and cache the OpenAI-compatible client."""
        if self._client is None:
            if not _HAS_OPENAI:
                raise ImportError(
                    "The 'openai' package is required for OpenRouterProvider. "
                    "Install it with: pip install openai"
                )
            self._client = openai.OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                default_headers={
                    "HTTP-Referer": "https://hackgpt.dev",
                    "X-Title": "HackGPT",
                },
            )
        return self._client  # type: ignore[return-value]

    def chat_completion(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Call OpenRouter chat completions via the OpenAI-compatible API."""
        client = self._get_client()
        try:
            response = client.chat.completions.create(
                model=model_id,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as exc:
            logger.error("OpenRouter chat completion failed: %s", exc)
            raise

    def is_available(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_name(self) -> str:
        return "OpenRouter"


# ---------------------------------------------------------------------------
# Provider Factory
# ---------------------------------------------------------------------------

# Mapping from ModelProvider enum values to their concrete classes.
_PROVIDER_CLASS_MAP: Dict[ModelProvider, type] = {
    ModelProvider.OPENAI: OpenAIProvider,
    ModelProvider.ANTHROPIC: AnthropicProvider,
    ModelProvider.GOOGLE: GoogleProvider,
    ModelProvider.DEEPSEEK: DeepSeekProvider,
    ModelProvider.GLM: GLMProvider,
    ModelProvider.LOCAL: OllamaProvider,
    ModelProvider.OPENROUTER: OpenRouterProvider,
}


class ProviderFactory:
    """Factory for lazily creating and caching provider instances.

    Usage::

        provider, model_info = ProviderFactory.get_provider_for_model("gpt-4o")
        answer = provider.chat_completion(
            model_id=model_info.model_id,
            messages=[{"role": "user", "content": "Hello!"}],
        )
    """

    _providers: Dict[ModelProvider, BaseProvider] = {}

    @classmethod
    def get_provider(cls, provider: ModelProvider) -> BaseProvider:
        """Return a cached provider instance, creating it on first access.

        Args:
            provider: The :class:`ModelProvider` enum member to instantiate.

        Returns:
            A :class:`BaseProvider` subclass instance for the requested
            provider.

        Raises:
            ValueError: If no concrete class is registered for *provider*.
        """
        if provider not in cls._providers:
            provider_cls = _PROVIDER_CLASS_MAP.get(provider)
            if provider_cls is None:
                raise ValueError(
                    f"No provider implementation registered for {provider!r}"
                )
            cls._providers[provider] = provider_cls()
            logger.debug("Created provider instance for %s", provider.value)
        return cls._providers[provider]

    @classmethod
    def get_provider_for_model(
        cls, model_id: str
    ) -> Tuple[BaseProvider, ModelInfo]:
        """Look up a model in the catalog and return its provider instance.

        Args:
            model_id: The model identifier as registered in
                :data:`MODEL_CATALOG`.

        Returns:
            A ``(provider_instance, model_info)`` tuple.

        Raises:
            ValueError: If *model_id* is not found in the catalog.
        """
        model_info = get_model_info(model_id)
        if model_info is None:
            raise ValueError(
                f"Model '{model_id}' not found in MODEL_CATALOG"
            )
        provider = cls.get_provider(model_info.provider)
        return provider, model_info

    @classmethod
    def get_available_providers(cls) -> List[ModelProvider]:
        """Return the list of providers that are currently available.

        A provider is considered *available* when its ``is_available()``
        method returns ``True`` (typically meaning an API key is
        configured or a local endpoint is reachable).
        """
        available: List[ModelProvider] = []
        for member in ModelProvider:
            try:
                provider = cls.get_provider(member)
                if provider.is_available():
                    available.append(member)
            except (ValueError, Exception) as exc:
                logger.debug(
                    "Provider %s not available: %s", member.value, exc
                )
        return available

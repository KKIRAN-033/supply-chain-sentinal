"""AI Provider abstraction layer.

Supports pluggable AI backends (Ollama, OpenAI, Gemini) with a guaranteed
deterministic security fallback that operates without network or GPU dependencies.
"""
import abc
import json
import logging
from typing import Optional, Dict, Any
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class AIProvider(abc.ABC):
    """Abstract base class for all AI providers."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider identifier."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if provider is online and ready."""
        pass

    @abc.abstractmethod
    def generate(self, prompt: str, system_prompt: str) -> Optional[str]:
        """Generate response given a system prompt and user prompt."""
        pass


class OllamaProvider(AIProvider):
    """Local Ollama LLM provider (Ollama runtime on localhost:11434)."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        self.base_url = getattr(settings, "OLLAMA_URL", base_url)
        self.model = getattr(settings, "OLLAMA_MODEL", model)

    @property
    def name(self) -> str:
        return f"ollama/{self.model}"

    def is_available(self) -> bool:
        try:
            with httpx.Client(timeout=1.5) as client:
                res = client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: str) -> Optional[str]:
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "format": "json",
            }
            with httpx.Client(timeout=30.0) as client:
                res = client.post(f"{self.base_url}/api/generate", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    return data.get("response")
        except Exception as e:
            logger.warning(f"Ollama generation failed: {e}. Falling back to deterministic analyst.")
        return None


class DeterministicAnalystProvider(AIProvider):
    """Guaranteed deterministic analyst provider.
    
    Always available, never hallucinates, mathematically grounded in backend evidence.
    """

    @property
    def name(self) -> str:
        return "deterministic-security-analyst"

    def is_available(self) -> bool:
        return True

    def generate(self, prompt: str, system_prompt: str) -> Optional[str]:
        # Handled directly by the Analyst Engine
        return None


def get_ai_provider() -> AIProvider:
    """Retrieve active AI provider, preferring Ollama if running, otherwise deterministic."""
    ollama = OllamaProvider()
    if ollama.is_available():
        return ollama
    return DeterministicAnalystProvider()

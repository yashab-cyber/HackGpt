from .advanced_engine import AdvancedAIEngine, AnalysisResult, PatternRecognizer, VulnerabilityCorrelator, ContextManager
from .model_registry import (
    ModelProvider, ModelInfo, MODEL_CATALOG,
    get_model_info, list_all_models, get_models_by_provider,
    get_available_providers
)
from .providers import ProviderFactory, BaseProvider


def get_advanced_ai_engine(model_id: str = None, provider: str = None):
    """Initialize and return the advanced AI engine with optional model selection"""
    return AdvancedAIEngine(model_id=model_id, provider=provider)


__all__ = [
    'AdvancedAIEngine',
    'AnalysisResult',
    'PatternRecognizer',
    'VulnerabilityCorrelator',
    'ContextManager',
    'get_advanced_ai_engine',
    'ModelProvider',
    'ModelInfo',
    'MODEL_CATALOG',
    'get_model_info',
    'list_all_models',
    'get_models_by_provider',
    'get_available_providers',
    'ProviderFactory',
    'BaseProvider',
]

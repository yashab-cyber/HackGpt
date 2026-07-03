# 🚀 HackGPT Enterprise Release Notes — Version 2026.07.beta.3

We are excited to announce the release of **HackGPT Enterprise Version 2026.07.beta.3**! This release introduces multi-provider AI model support, runtime model switching, automatic provider fallback, and a comprehensive model catalog of 26+ advanced AI models.

---

## 🌟 What's New in Version 2026.07.beta.3

### 1. Multi-Provider AI Model Engine
* **Expanded Provider Ecosystem**: Integrated 7 key AI providers under a unified abstract client interface (`BaseProvider`):
  * **OpenAI**: Support for next-generation reasoning and multimodal models including `gpt-5`, `gpt-5.6`, `o3`, `o4-mini`, `gpt-4o`, and `gpt-4o-mini`.
  * **Anthropic**: Support for `claude-sonnet-5` (`claude-sonnet-4-20250514`), `claude-opus-4.8` (`claude-opus-4-20250918`), and `claude-haiku-3.5`. Calls the Messages API directly via raw REST request layer.
  * **Google Gemini**: Support for `gemini-3.5-flash`, `gemini-3.1-pro`, `gemini-2.5-pro`, and `gemini-2.5-flash` with massive 1M-2M token context windows.
  * **DeepSeek**: Support for `deepseek-r1` (reasoning with CoT) and `deepseek-v3` (`deepseek-chat`) via custom OpenAI-compatible client.
  * **GLM (Zhipu)**: Support for bilingual language models `glm-5.2` and `glm-4-plus`.
  * **Local LLMs (Ollama)**: Offline capabilities for local models including `llama3.3:70b`, `llama3.2:3b`, `mistral:7b`, `codellama:13b`, `qwen2.5:32b`, `deepseek-r1:14b`, and `phi-4:14b`.
  * **OpenRouter**: Access to 100+ public models through the OpenRouter aggregator using the `openrouter/auto` ID.

### 2. Runtime Model Switching & Fallback Chain
* **On-the-fly Switch**: Added `engine.set_model(model_id)` to let developers change models programmatically or dynamically during assessments.
* **Provider Fallback**: A three-tier fallback chain ensures high-availability during assessments:
  1. Selected model provider API
  2. Direct OpenAI API key fallback (if `OPENAI_API_KEY` is present)
  3. Local offline models (Hugging Face / Ollama) as the ultimate fail-safe

### 3. Centralized Model Registry & Client Factory
* Introduced `ai_engine/model_registry.py` managing the complete `MODEL_CATALOG` with token limits, tool-calling capabilities, and provider metadata.
* Introduced `ai_engine/providers.py` hosting concrete client classes and `ProviderFactory` for lazy instantiation and caching.

### 4. Robust AI Provider Unit Tests & Pathing
* Added `tests/unit/test_ai_providers.py` checking catalog completeness, metadata queries, and API key environment checks.
* Modified the root `conftest.py` testing configuration to allow importing real submodules from the `ai_engine` package during unit runs while keeping external database connections fully isolated.

---

## 🛠️ Quick Start with version 2026.07.beta.3

1. **Configure Environment**:
   Copy `.env.example` to `.env` and provide your API keys:
   ```bash
   HACKGPT_MODEL=gpt-5
   ANTHROPIC_API_KEY=your_key
   GOOGLE_API_KEY=your_key
   DEEPSEEK_API_KEY=your_key
   ```

2. **Select Model in Code**:
   ```python
   from ai_engine import get_advanced_ai_engine
   
   # Initialize with Claude Sonnet 5
   engine = get_advanced_ai_engine(model_id='claude-sonnet-5')
   ```

3. **Verify Installation**:
   ```bash
   pytest tests/unit/ -v
   python3 test_installation.py
   ```

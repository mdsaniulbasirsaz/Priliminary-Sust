import os

from dotenv import load_dotenv

load_dotenv()


OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
PORT = int(os.getenv("PORT", "8000"))
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "25"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "500"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))

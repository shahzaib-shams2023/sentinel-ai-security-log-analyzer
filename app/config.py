from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "SentinelAI Threat Intelligence & SIEM Log Analyzer"
    host: str = "0.0.0.0"
    port: int = 8002
    environment: str = "development"

    brute_force_threshold: int = 5
    anomaly_sensitivity: float = 0.75

    llm_api_key: Optional[str] = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.1

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()


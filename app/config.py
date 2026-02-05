"""
Configuration management for the Agentic Honeypot API.
Uses environment variables with sensible defaults.
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    api_key: str = "honeypot-secure-key-2026"
    debug: bool = False
    
    # OpenRouter Configuration (primary - FREE models available)
    openrouter_api_key: Optional[str] = None
    openrouter_model: str = "google/gemma-2-9b-it:free"  # Confirmed free model!
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    
    # Gemini Configuration (backup)
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-1.5-flash"
    
    # Detection Thresholds
    scam_confidence_threshold: float = 0.6
    
    # App Info
    app_name: str = "Agentic Honeypot API"
    app_version: str = "1.0.0"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

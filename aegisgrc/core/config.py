import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis GRC"
    API_V1_STR: str = "/api/v1"
    
    # Environment config
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Database Settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegis_grc.db")
    
    # AI SDK Settings
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # OPA Compiler path
    OPA_PATH: str = os.getenv("OPA_PATH", "opa")

    class Config:
        case_sensitive = True


settings = Settings()

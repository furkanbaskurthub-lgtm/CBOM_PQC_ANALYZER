"""
PQC-Ready Analyzer - Konfigürasyon
"""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Ana Konfigürasyon Sınıfı"""
    
    # Temel Yollar
    BASE_DIR = Path(__file__).parent.absolute()
    OUTPUT_DIR = BASE_DIR / "output"
    TEMP_DIR = Path(os.getenv("TEMP_DIR", "/tmp/pqc-analyzer"))
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = BASE_DIR / "logs" / "analyzer.log"
    
    # LLM Konfigürasyonu
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "mock")
    USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"
    
    # OpenAI
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.3"))
    OPENAI_MAX_TOKENS = int(os.getenv("OPENAI_MAX_TOKENS", "500"))
    
    # HuggingFace
    HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
    HUGGINGFACE_MODEL = os.getenv("HUGGINGFACE_MODEL", "mistralai/Mistral-7B-v0.1")
    
    # Ollama
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
    
    # Analiz Seçenekleri
    ENABLE_BINARY_ANALYSIS = os.getenv("ENABLE_BINARY_ANALYSIS", "true").lower() == "true"
    ENABLE_SOURCE_CODE_ANALYSIS = os.getenv("ENABLE_SOURCE_CODE_ANALYSIS", "true").lower() == "true"
    ENABLE_LIBRARY_DETECTION = True
    
    # Timeout
    API_TIMEOUT = int(os.getenv("API_TIMEOUT", "30"))
    ANALYSIS_TIMEOUT = int(os.getenv("ANALYSIS_TIMEOUT", "300"))
    
    @classmethod
    def ensure_directories(cls):
        """Gerekli klasörleri oluştur"""
        cls.OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
        cls.TEMP_DIR.mkdir(exist_ok=True, parents=True)
        (cls.BASE_DIR / "logs").mkdir(exist_ok=True, parents=True)
    
    @classmethod
    def get_llm_config(cls) -> dict:
        """LLM konfigürasyonunu döndür"""
        if cls.LLM_PROVIDER == "openai":
            return {
                "provider": "openai",
                "api_key": cls.OPENAI_API_KEY,
                "model": cls.OPENAI_MODEL,
                "temperature": cls.OPENAI_TEMPERATURE,
                "max_tokens": cls.OPENAI_MAX_TOKENS,
            }
        elif cls.LLM_PROVIDER == "huggingface":
            return {
                "provider": "huggingface",
                "api_key": cls.HUGGINGFACE_API_KEY,
                "model": cls.HUGGINGFACE_MODEL,
            }
        elif cls.LLM_PROVIDER == "ollama":
            return {
                "provider": "ollama",
                "base_url": cls.OLLAMA_BASE_URL,
                "model": cls.OLLAMA_MODEL,
            }
        else:
            return {"provider": "mock"}
    
    @classmethod
    def validate(cls) -> bool:
        """Konfigürasyonu doğrula"""
        errors = []
        
        if cls.USE_LLM:
            if cls.LLM_PROVIDER == "openai" and not cls.OPENAI_API_KEY:
                errors.append("OpenAI provider seçildi ancak OPENAI_API_KEY tanımlanmadı")
            
            if cls.LLM_PROVIDER == "huggingface" and not cls.HUGGINGFACE_API_KEY:
                errors.append("HuggingFace provider seçildi ancak HUGGINGFACE_API_KEY tanımlanmadı")
        
        if errors:
            print("❌ Konfigürasyon Hataları:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True


# Startup
if __name__ == "__main__":
    Config.ensure_directories()
    
    print("✅ PQC-Ready Analyzer Konfigürasyonu")
    print(f"  Base Dir: {Config.BASE_DIR}")
    print(f"  Output Dir: {Config.OUTPUT_DIR}")
    print(f"  LLM Provider: {Config.LLM_PROVIDER}")
    print(f"  Use LLM: {Config.USE_LLM}")
    print(f"  Validation: {'✅ Geçti' if Config.validate() else '❌ Başarısız'}")

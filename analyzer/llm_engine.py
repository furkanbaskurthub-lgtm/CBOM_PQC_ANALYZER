"""
LLM Analiz Engine - Kod Analizi ve İnterpretasyonu
OpenAI API veya HuggingFace kullanarak karmaşık kriptografik kullanımları analiz eder
"""

import os
import json
import re
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from pydantic import BaseModel, Field

# İsteğe bağlı kütüphane importları
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class AnalysisResult:
    """LLM Analiz Sonucu"""
    success: bool
    algorithm: Optional[str] = None
    key_length: Optional[int] = None
    mode: Optional[str] = None
    is_pqc_safe: bool = False
    confidence: float = 0.5
    raw_response: Optional[str] = None
    error: Optional[str] = None


class LLMConfig(BaseModel):
    """LLM Konfigürasyonu"""
    provider: str = Field("openai", description="LLM sağlayıcısı (openai, huggingface, ollama)")
    api_key: Optional[str] = Field(None, description="API anahtarı")
    model: str = Field("gpt-3.5-turbo", description="Model adı")
    temperature: float = Field(0.3, ge=0.0, le=1.0, description="Sıcaklık (determinizm)")
    max_tokens: int = Field(500, ge=100, description="Maksimum token sayısı")
    timeout: int = Field(30, description="Timeout (saniye)")


SYSTEM_PROMPT = """Sen bir kriptografi uzmanısı ve kod analiz sistemisin.
Verilen kod bloklarında kullanılan kriptografik algoritmaları, anahtar uzunluklarını 
ve güvenlik parametrelerini tespit etmelisin.

Cevaplarını SADECE aşağıdaki JSON formatında ver:
{
    "algorithm": "algoritma_adı",
    "key_length": anahtar_uzunluğu_veya_null,
    "mode": "mod_adı_veya_null",
    "padding": "padding_türü_veya_null",
    "is_pqc_safe": true/false,
    "confidence": 0.0_ile_1.0_arasında,
    "notes": "ek notlar"
}

Notlar:
- PQC Safe (Post-Quantum Cryptography): Kyber, ML-KEM, Dilithium, ML-DSA, SLH-DSA, Falcon
- Algoritmaları BÜYÜK HARFLE yaz (RSA, AES, SHA-256, vb.)
- Key_length sayı olmalı (örn: 256, 2048)
- Confidence 0.5 ile başla, bulguya göre ayarla (0.9+ için çok emin ol)
"""

ANALYSIS_PROMPT = """Aşağıdaki kod bloğunda kullanılan kriptografik algoritmaları analiz et:

```
{code_snippet}
```

JSON formatında yanıt ver."""


class LLMAnalysisEngine:
    """LLM Tabanlı Analiz Motoru"""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Motoru başlat
        
        Args:
            config: LLM konfigürasyonu
        """
        if config is None:
            config = LLMConfig()
        
        self.config = config
        self._validate_dependencies()
        self._setup_client()
    
    def _validate_dependencies(self):
        """Gerekli bağımlılıkları kontrol et"""
        if self.config.provider == "openai" and not HAS_OPENAI:
            raise ImportError("OpenAI provider seçildi ancak 'openai' kütüphanesi yüklü değil. "
                            "Yükle: pip install openai")
        
        if self.config.provider == "huggingface" and not HAS_REQUESTS:
            raise ImportError("HuggingFace provider seçildi ancak 'requests' kütüphanesi yüklü değil. "
                            "Yükle: pip install requests")
    
    def _setup_client(self):
        """LLM client'ı kur"""
        if self.config.provider == "openai":
            if not self.config.api_key:
                self.config.api_key = os.getenv("OPENAI_API_KEY")
            
            if HAS_OPENAI:
                openai.api_key = self.config.api_key
    
    def analyze_code_block(self, code_snippet: str) -> AnalysisResult:
        """
        Kod bloğunu LLM ile analiz et
        
        Args:
            code_snippet: Analiz edilecek kod
            
        Returns:
            Analiz sonucu
        """
        if not code_snippet or len(code_snippet.strip()) == 0:
            return AnalysisResult(
                success=False,
                error="Kod bloğu boş veya geçersiz"
            )
        
        try:
            if self.config.provider == "openai":
                return self._analyze_with_openai(code_snippet)
            elif self.config.provider == "huggingface":
                return self._analyze_with_huggingface(code_snippet)
            elif self.config.provider == "ollama":
                return self._analyze_with_ollama(code_snippet)
            else:
                return self._mock_analysis(code_snippet)
        
        except Exception as e:
            return AnalysisResult(
                success=False,
                error=f"Analiz hatası: {str(e)}"
            )
    
    def _analyze_with_openai(self, code_snippet: str) -> AnalysisResult:
        """OpenAI API ile analiz yap"""
        if not HAS_OPENAI:
            return self._mock_analysis(code_snippet)
        
        try:
            message = openai.ChatCompletion.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": ANALYSIS_PROMPT.format(code_snippet=code_snippet)}
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout
            )
            
            response_text = message.choices[0].message.content
            return self._parse_json_response(response_text)
        
        except Exception as e:
            return AnalysisResult(
                success=False,
                raw_response=str(e),
                error=f"OpenAI API hatası: {str(e)}"
            )
    
    def _analyze_with_huggingface(self, code_snippet: str) -> AnalysisResult:
        """HuggingFace API ile analiz yap"""
        if not HAS_REQUESTS:
            return self._mock_analysis(code_snippet)
        
        try:
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            payload = {
                "inputs": ANALYSIS_PROMPT.format(code_snippet=code_snippet),
                "parameters": {"max_length": self.config.max_tokens}
            }
            
            response = requests.post(
                f"https://api-inference.huggingface.co/models/{self.config.model}",
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result[0].get("generated_text", "")
                return self._parse_json_response(response_text)
            else:
                return AnalysisResult(
                    success=False,
                    error=f"HuggingFace API hatası: {response.status_code}"
                )
        
        except Exception as e:
            return AnalysisResult(
                success=False,
                error=f"HuggingFace analiz hatası: {str(e)}"
            )
    
    def _analyze_with_ollama(self, code_snippet: str) -> AnalysisResult:
        """Ollama lokal LLM ile analiz yap"""
        if not HAS_REQUESTS:
            return self._mock_analysis(code_snippet)
        
        try:
            full_prompt = (
                f"{SYSTEM_PROMPT}\n\n"
                f"{ANALYSIS_PROMPT.format(code_snippet=code_snippet)}\n\n"
                "Sadece geçerli bir JSON nesnesi döndür. Açıklama ekleme."
            )

            payload = {
                "model": self.config.model,
                "prompt": full_prompt,
                "stream": False,
                "temperature": self.config.temperature,
                "format": "json"
            }
            
            response = requests.post(
                "http://localhost:11434/api/generate",
                json=payload,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get("response", "")

                # Ollama format=json ile genellikle yalın JSON metni döner.
                # Doğrudan parse etmeyi dene, olmazsa mevcut esnek parser'a düş.
                try:
                    data = json.loads(response_text)
                    return AnalysisResult(
                        success=True,
                        algorithm=data.get("algorithm"),
                        key_length=data.get("key_length"),
                        mode=data.get("mode"),
                        is_pqc_safe=data.get("is_pqc_safe", False),
                        confidence=data.get("confidence", 0.5),
                        raw_response=response_text
                    )
                except Exception:
                    pass

                return self._parse_json_response(response_text)
            else:
                return AnalysisResult(
                    success=False,
                    error=f"Ollama API hatası: {response.status_code}"
                )
        
        except Exception as e:
            return AnalysisResult(
                success=False,
                error=f"Ollama analiz hatası: {str(e)}"
            )
    
    def _mock_analysis(self, code_snippet: str) -> AnalysisResult:
        """Mock/Fallback analiz (öğrenme amaçlı)"""
        # Basit regex-temelli fallback
        analysis = {
            "algorithm": "unknown",
            "key_length": None,
            "mode": None,
            "is_pqc_safe": False,
            "confidence": 0.3,
            "notes": "Mock analiz - gerçek LLM kullanılmıyor"
        }
        
        # Bazı temel desenler
        patterns = {
            r"(RSA|rsa)": {"algorithm": "RSA", "confidence": 0.7},
            r"(AES|aes)": {"algorithm": "AES", "confidence": 0.7},
            r"(SHA-?256|sha256)": {"algorithm": "SHA-256", "confidence": 0.8},
            r"(SHA-?512|sha512)": {"algorithm": "SHA-512", "confidence": 0.8},
            r"(MD5|md5)": {"algorithm": "MD5", "confidence": 0.8},
            r"(kyber|ml-kem)": {"algorithm": "Kyber/ML-KEM", "is_pqc_safe": True, "confidence": 0.9},
            r"(dilithium|ml-dsa)": {"algorithm": "Dilithium/ML-DSA", "is_pqc_safe": True, "confidence": 0.9},
            r"(\d{3,4})(bit|-bit)": {"key_length": int, "confidence": 0.7},
            r"(gcm|cbc|ecb|ctr)": {"mode": "GCM/CBC/ECB/CTR", "confidence": 0.6},
        }
        
        for pattern, result in patterns.items():
            if re.search(pattern, code_snippet, re.IGNORECASE):
                analysis.update({k: v for k, v in result.items() if k != "key_length" or v != int})
                
                # Key length için özel işlem
                if "key_length" in result and result["key_length"] == int:
                    match = re.search(r'(\d{3,4})\s*(bit|bitleng|-bit)', code_snippet, re.IGNORECASE)
                    if match:
                        analysis["key_length"] = int(match.group(1))
        
        return AnalysisResult(
            success=True,
            algorithm=analysis.get("algorithm"),
            key_length=analysis.get("key_length"),
            mode=analysis.get("mode"),
            is_pqc_safe=analysis.get("is_pqc_safe", False),
            confidence=analysis.get("confidence", 0.3),
            raw_response=f"Mock: {analysis}"
        )
    
    def _parse_json_response(self, response_text: str) -> AnalysisResult:
        """
        JSON yanıtını parse et
        
        Args:
            response_text: LLM'den gelen yanıt
            
        Returns:
            Parse edilmiş analiz sonucu
        """
        # JSON bloğunu yanıttan çıkart
        json_pattern = r'\{[\s\S]*\}'
        matches = re.finditer(json_pattern, response_text)
        
        for match in matches:
            try:
                json_text = match.group(0)
                data = json.loads(json_text)
                
                return AnalysisResult(
                    success=True,
                    algorithm=data.get("algorithm"),
                    key_length=data.get("key_length"),
                    mode=data.get("mode"),
                    is_pqc_safe=data.get("is_pqc_safe", False),
                    confidence=data.get("confidence", 0.5),
                    raw_response=json_text
                )
            except json.JSONDecodeError:
                continue
        
        # JSON bulunamadı
        return AnalysisResult(
            success=False,
            raw_response=response_text,
            error="Yanıttan geçerli JSON çıkartılamadı"
        )
    
    def analyze_multiple_snippets(self, snippets: List[str]) -> List[AnalysisResult]:
        """
        Birden fazla kod bloğunu analiz et
        
        Args:
            snippets: Kod bloğu listesi
            
        Returns:
            Analiz sonuçları listesi
        """
        results = []
        for snippet in snippets:
            result = self.analyze_code_block(snippet)
            results.append(result)
        
        return results
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Mevcut konfigürasyonu döndür"""
        return {
            "provider": self.config.provider,
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "timeout": self.config.timeout
        }


# Test
if __name__ == "__main__":
    # Mock analiz örneği
    config = LLMConfig(provider="mock")
    engine = LLMAnalysisEngine(config)
    
    test_code = """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    """
    
    result = engine.analyze_code_block(test_code)
    print(f"Başarı: {result.success}")
    print(f"Algoritma: {result.algorithm}")
    print(f"PQC Safe: {result.is_pqc_safe}")
    print(f"Confidence: {result.confidence}")
    print(f"Hata: {result.error}")

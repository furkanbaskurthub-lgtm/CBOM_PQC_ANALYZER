"""
CycloneDX v1.5 uyumlu Kriptografik Varlık Şeması
OWASP CycloneDX Crypto-Asset standartlarına göre tasarlandı
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Literal
from datetime import datetime
from enum import Enum


class PrimitiveType(str, Enum):
    """Kriptografik ilkel türleri"""
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    HMAC = "hmac"
    ASYMMETRIC = "asymmetric"
    SIGNING = "signing"
    KEY_EXCHANGE = "key-exchange"
    KEY_DERIVATION = "key-derivation"
    MAC = "mac"
    AUTHENTICATED_ENCRYPTION = "authenticated-encryption"


class CryptoFunction(str, Enum):
    """Kriptografik fonksiyon türleri"""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    HASH = "hash"
    HMAC = "hmac"
    KEY_AGREEMENT = "key-agreement"
    KEY_DERIVATION = "key-derivation"
    KEY_GENERATION = "key-generation"
    RANDOM_NUMBER_GENERATION = "random-number-generation"


class AlgorithmDetails(BaseModel):
    """Algoritma detayları"""
    name: str = Field(..., description="Algoritmanın adı (RSA, AES, SHA-256, etc.)")
    type: PrimitiveType = Field(..., description="İlkel tür")
    key_length: Optional[int] = Field(None, description="Anahtar uzunluğu (bit cinsinden)")
    mode: Optional[str] = Field(None, description="Çalışma modu (CBC, GCM, ECB, etc.)")
    padding: Optional[str] = Field(None, description="Padding şeması (PKCS7, OAEP, etc.)")
    is_pqc_safe: bool = Field(False, description="NIST PQC standartlarına uygun mu?")
    pqc_status: Optional[str] = Field(None, description="PQC durumu (standardized, in-progress, legacy)")
    

class CryptoAsset(BaseModel):
    """CycloneDX Crypto-Asset Bileşeni"""
    ref: str = Field(..., description="Benzersiz referans ID")
    algorithm: AlgorithmDetails = Field(..., description="Algoritma detayları")
    crypto_functions: List[CryptoFunction] = Field(default_factory=list, description="Kullanılan fonksiyonlar")
    oid: Optional[str] = Field(None, description="Object Identifier (OID)")
    source: str = Field("unknown", description="Kaynak (binary, source-code, library, etc.)")
    location: Optional[str] = Field(None, description="Dosya yolu veya konum")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Tespit güvenilirliği (0.0-1.0)")
    risk_level: Literal["low", "medium", "high", "critical"] = Field("medium", description="Risk seviyesi")
    notes: Optional[str] = Field(None, description="Ek notlar")


class CryptoBOM(BaseModel):
    """Tam CBOM (Cryptography Bill of Materials)"""
    version: str = Field("1.0", description="CBOM versiyonu")
    cyclonedx_version: str = Field("1.5", description="CycloneDX versiyonu")
    bom_ref: str = Field(..., description="BOM referans ID")
    spec_version: str = Field("1.5", description="Spec versiyonu")
    
    metadata: Dict = Field(default_factory=dict, description="Meta veriler")
    created: datetime = Field(default_factory=datetime.utcnow, description="Oluşturma tarihi")
    
    target_file: str = Field(..., description="Analiz edilen hedef dosya")
    target_type: Literal["binary", "source-code", "library", "application"] = Field(
        ..., description="Hedef türü"
    )
    
    crypto_assets: List[CryptoAsset] = Field(default_factory=list, description="Bulunan kriptografik varlıklar")
    
    summary: Dict = Field(default_factory=dict, description="Özet istatistikler")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Genel risk skoru (0-100)")


class RiskAssessment(BaseModel):
    """Risk Değerlendirmesi"""
    algorithm: str = Field(..., description="Algoritma adı")
    base_risk: float = Field(..., ge=0.0, le=100.0, description="Temel risk skoru")
    pqc_compliance: float = Field(0.0, ge=0.0, le=100.0, description="PQC uyumluluğu")
    final_risk: float = Field(..., ge=0.0, le=100.0, description="Son risk skoru")
    recommendation: str = Field(..., description="Öneriler")
    mitigation: Optional[str] = Field(None, description="Risk azaltma stratejileri")


# NIST PQC Risk Mapping
NIST_PQC_RISK_MAP = {
    # Yüksek Risk - Güvenliğin tehdit altında olduğu eski algoritmalar
    "RSA": {"base": 85.0, "pqc": 0.0, "status": "legacy"},
    "DSA": {"base": 90.0, "pqc": 0.0, "status": "legacy"},
    "ECDSA": {"base": 75.0, "pqc": 0.0, "status": "legacy"},
    "ECDH": {"base": 75.0, "pqc": 0.0, "status": "legacy"},
    "MD5": {"base": 95.0, "pqc": 0.0, "status": "broken"},
    "SHA-1": {"base": 80.0, "pqc": 0.0, "status": "legacy"},
    
    # Orta Risk - Hala güvenli ancak uzun vadede sorun
    "SHA-256": {"base": 25.0, "pqc": 0.0, "status": "secure"},
    "SHA-512": {"base": 20.0, "pqc": 0.0, "status": "secure"},
    "AES-128": {"base": 30.0, "pqc": 0.0, "status": "secure"},
    "AES-256": {"base": 15.0, "pqc": 0.0, "status": "secure"},
    
    # Düşük Risk - PQC Standardlarına uygun
    "Kyber": {"base": 10.0, "pqc": 100.0, "status": "standardized"},
    "ML-KEM": {"base": 10.0, "pqc": 100.0, "status": "standardized"},
    "Dilithium": {"base": 10.0, "pqc": 100.0, "status": "standardized"},
    "ML-DSA": {"base": 10.0, "pqc": 100.0, "status": "standardized"},
    "SLH-DSA": {"base": 15.0, "pqc": 100.0, "status": "standardized"},
    "Falcon": {"base": 12.0, "pqc": 95.0, "status": "standardized"},
}


def calculate_risk_score(algorithm: str, key_length: Optional[int] = None) -> RiskAssessment:
    """
    NIST PQC standartlarına göre risk puanı hesapla
    
    Args:
        algorithm: Algoritma adı
        key_length: Anahtar uzunluğu (isteğe bağlı)
    
    Returns:
        RiskAssessment: Risk değerlendirmesi
    """
    base_info = NIST_PQC_RISK_MAP.get(algorithm, {"base": 50.0, "pqc": 0.0, "status": "unknown"})
    
    base_risk = base_info["base"]
    pqc_compliance = base_info["pqc"]
    final_risk = (base_risk * 0.7) + (pqc_compliance * 0.3)
    
    # Anahtar uzunluğuna göre ayarlama
    if key_length and key_length < 128:
        final_risk += 15.0
    elif key_length and key_length > 256:
        final_risk -= 5.0
    
    status = base_info["status"]
    
    if final_risk >= 80:
        recommendation = "ACIL: Bu algoritmanın kullanımını durdur ve modern alternatifle değiştir"
    elif final_risk >= 50:
        recommendation = "UYAR: Kısa vadede bu algoritmanın phasing-out planını yap"
    elif final_risk >= 25:
        recommendation = "İYİ: Algoritma güvenli ancak PQC dönüşümünü planla"
    else:
        recommendation = "HARIKA: Bu algoritma PQC criteria'sını karşılıyor"
    
    mitigation = None
    if status == "legacy":
        mitigation = "Kyber/ML-KEM (anahtar anlaşması) veya ML-DSA (imza) kullanarak upgrade et"
    elif status == "broken":
        mitigation = "Derhal güvenli bir hash fonksiyonuna (SHA-256+) geçiş yap"
    
    return RiskAssessment(
        algorithm=algorithm,
        base_risk=base_risk,
        pqc_compliance=pqc_compliance,
        final_risk=min(final_risk, 100.0),
        recommendation=recommendation,
        mitigation=mitigation
    )


if __name__ == "__main__":
    # Test amaçlı örnek
    example_asset = CryptoAsset(
        ref="crypto-1",
        algorithm=AlgorithmDetails(
            name="AES-256-GCM",
            type=PrimitiveType.BLOCK_CIPHER,
            key_length=256,
            mode="GCM",
            is_pqc_safe=False,
            pqc_status="legacy"
        ),
        crypto_functions=[CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT],
        source="binary",
        risk_level="medium"
    )
    
    cbom = CryptoBOM(
        bom_ref="cbom-1",
        target_file="/path/to/binary",
        target_type="binary",
        crypto_assets=[example_asset]
    )
    
    print(cbom.model_dump_json(indent=2))

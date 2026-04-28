"""
PQC-Ready Analyzer - Ana Uygulama
Tüm modülleri orkestrasyonla yönetir
"""

import json
import os
import uuid
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import asdict
from dotenv import load_dotenv

from models.crypto_schema import (
    CryptoBOM, CryptoAsset, AlgorithmDetails, PrimitiveType,
    CryptoFunction, calculate_risk_score, NIST_PQC_RISK_MAP
)
from analyzer.static_engine import StaticAnalysisEngine
from analyzer.llm_engine import LLMAnalysisEngine, LLMConfig, AnalysisResult
from analyzer.validation_engine import ValidationEngine
from analyzer.decision_engine import DecisionEngine
from models.label_schema import EvidenceItem, LabeledCryptoAsset
from utils.dataset_builder import DEFAULT_INSTRUCTION, build_instruction_records, write_jsonl


class PQCReadyAnalyzer:
    """Ana Analyzer Sınıfı - Tüm araçları orkestrasyonla yönetir"""
    
    def __init__(self, output_dir: str = "output", llm_cache_enabled: bool = True):
        """
        Analyzer'ı başlat
        
        Args:
            output_dir: Çıktı klasörü
        """
        load_dotenv()

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.static_engine = StaticAnalysisEngine()
        
        # LLM engine konfigürasyonu .env üzerinden okunur; eksik anahtar varsa mock'a düşer.
        provider = os.getenv("LLM_PROVIDER", "mock").strip().lower()
        llm_config = LLMConfig(
            provider=provider,
            api_key=(
                os.getenv("OPENAI_API_KEY")
                if provider == "openai"
                else os.getenv("HUGGINGFACE_API_KEY")
            ),
            model=(
                os.getenv("OPENAI_MODEL", "gpt-4o-mini")
                if provider == "openai"
                else (
                    os.getenv("HUGGINGFACE_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
                    if provider == "huggingface"
                    else os.getenv("OLLAMA_MODEL", "llama3.1")
                )
            ),
            temperature=float(os.getenv("OPENAI_TEMPERATURE", "0.3")),
            max_tokens=int(os.getenv("OPENAI_MAX_TOKENS", "500")),
            timeout=int(os.getenv("API_TIMEOUT", "30")),
        )

        if provider in {"openai", "huggingface"} and not llm_config.api_key:
            llm_config = LLMConfig(provider="mock")

        self.llm_engine = LLMAnalysisEngine(llm_config)
        self.validation_engine = ValidationEngine()
        self.decision_engine = DecisionEngine()

        self.llm_cache_enabled = llm_cache_enabled
        self.llm_snippet_cache: Dict[str, Dict[str, Any]] = {}
        
        self.cbom_results: Dict[str, CryptoBOM] = {}
        self._last_static_results: Dict[str, Dict[str, Any]] = {}
    
    def analyze_target(
        self,
        target_path: str,
        use_llm: bool = False,
        llm_candidate_only: bool = False,
        llm_min_confidence: float = 0.0,
        llm_max_snippets: int = 4,
    ) -> CryptoBOM:
        """
        Hedef dosyayı analiz et
        
        Args:
            target_path: Dosya yolu
            use_llm: LLM analizini kullan mı?
            
        Returns:
            CBOM sonucu
        """
        target = Path(target_path)
        
        if not target.exists():
            raise FileNotFoundError(f"Hedef dosya bulunamadı: {target_path}")
        
        # Statik analiz yap
        static_results = self.static_engine.analyze_file(str(target))
        
        # CBOM oluştur
        cbom_ref = f"cbom-{uuid.uuid4().hex[:8]}"
        
        cbom = CryptoBOM(
            bom_ref=cbom_ref,
            target_file=str(target),
            target_type="binary" if static_results["file_type"] in ["ELF", "PE"] else "source-code",
            created=datetime.utcnow()
        )
        
        # Statik analiz sonuçlarından varlıklar oluştur
        for algo_name, algo_info in static_results.get("crypto_assets", {}).items():
            # Risk puanlaması
            risk = calculate_risk_score(algo_name)
            
            crypto_asset = CryptoAsset(
                ref=f"crypto-{uuid.uuid4().hex[:8]}",
                algorithm=AlgorithmDetails(
                    name=algo_name,
                    type=self._infer_primitive_type(algo_name),
                    is_pqc_safe=risk.pqc_compliance > 50.0,
                    pqc_status="standardized" if risk.pqc_compliance > 80 else "legacy"
                ),
                crypto_functions=self._infer_functions(algo_name),
                source="binary" if static_results["file_type"] in ["ELF", "PE"] else "source-code",
                confidence=algo_info.get("confidence", 0.7),
                risk_level=self._risk_level_from_score(risk.final_risk),
                location=str(target)
            )
            
            cbom.crypto_assets.append(crypto_asset)
        
        # LLM analizi yapılırsa kaynak kod veya binary için zenginleştirme uygula
        if use_llm:
            allow_llm = True
            if llm_candidate_only:
                allow_llm = self._is_llm_candidate(
                    cbom,
                    static_results,
                    llm_min_confidence=llm_min_confidence,
                )

            if allow_llm:
                if static_results["file_type"] == "TEXT":
                    self._enhance_with_llm(cbom, target, max_snippets=llm_max_snippets)
                elif static_results["file_type"] in ["ELF", "PE", "BINARY"]:
                    self._enhance_binary_with_llm(cbom, target, static_results)
        
        # Özet ve risk puanlaması hesapla
        self._compute_summary(cbom)
        
        # Sonuç kaydet
        self.cbom_results[cbom_ref] = cbom
        self._last_static_results[cbom_ref] = static_results
        
        return cbom

    def generate_labeled_assets(
        self,
        cbom: CryptoBOM,
        static_results: Optional[Dict[str, Any]] = None,
    ) -> List[LabeledCryptoAsset]:
        """CBOM varlıklarını V2 etiketli şemaya dönüştür ve doğrula."""
        if static_results is None:
            static_results = self._last_static_results.get(cbom.bom_ref, {})

        labeled_assets: List[LabeledCryptoAsset] = []
        for asset in cbom.crypto_assets:
            evidence_items = self._collect_asset_evidence(asset.algorithm.name, static_results)
            labeled = self.validation_engine.validate_asset(asset, evidence_items)
            labeled.decision = self.decision_engine.evaluate_asset(labeled)
            labeled_assets.append(labeled)

        return labeled_assets

    def _collect_asset_evidence(self, algorithm: str, static_results: Dict[str, Any]) -> List[EvidenceItem]:
        """Statik analiz çıktısından algoritma bazlı evidence kayıtları üret."""
        raw_evidence = static_results.get("evidence", [])
        evidence_items: List[EvidenceItem] = []
        seen: Set[Tuple[Any, ...]] = set()

        for item in raw_evidence:
            if item.get("algorithm") != algorithm:
                continue

            dedup_key = (
                item.get("file_path"),
                item.get("line_start"),
                item.get("line_end"),
                item.get("snippet"),
                item.get("function_name"),
                item.get("source_type"),
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            evidence_items.append(
                EvidenceItem(
                    file_path=item.get("file_path", "unknown"),
                    language=item.get("language"),
                    line_start=item.get("line_start"),
                    line_end=item.get("line_end"),
                    function_name=item.get("function_name"),
                    snippet=item.get("snippet"),
                    context_before=item.get("context_before"),
                    context_after=item.get("context_after"),
                    detector=item.get("detector", "static"),
                    source_type=item.get("source_type", "source"),
                )
            )

        if not evidence_items:
            evidence_items.append(
                EvidenceItem(
                    file_path=static_results.get("file", "unknown"),
                    detector="fallback",
                    source_type="source",
                    snippet=f"Detected algorithm: {algorithm}",
                )
            )

        return evidence_items

    def save_labeled_json(
        self,
        labeled_assets: List[LabeledCryptoAsset],
        filename: str = "labeled_assets_v2.json",
    ) -> Path:
        """V2 etiketli varlıkları JSON dosyasına kaydet."""
        output_file = self.output_dir / filename
        payload = [asset.model_dump() for asset in labeled_assets]
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return output_file

    def export_instruction_dataset(
        self,
        labeled_assets: List[LabeledCryptoAsset],
        output_filename: str = "crypto_instruction_dataset.jsonl",
        instruction: Optional[str] = None,
        training_only: bool = False,
    ) -> Path:
        """Labeled çıktılardan LLM instruction JSONL dataset üret."""
        if training_only:
            labeled_assets = [a for a in labeled_assets if a.decision and a.decision.include]
        records = build_instruction_records(labeled_assets, instruction=instruction or DEFAULT_INSTRUCTION)
        output_file = self.output_dir / output_filename
        write_jsonl(records, str(output_file))
        return output_file

    def split_labeled_assets_by_decision(self, labeled_assets: List[LabeledCryptoAsset]) -> Dict[str, List[LabeledCryptoAsset]]:
        """Varlıkları decision çıktısına göre training/review/dropped olarak ayır."""
        return self.decision_engine.split_by_decision(labeled_assets)

    def export_decision_datasets(
        self,
        labeled_assets: List[LabeledCryptoAsset],
        instruction: Optional[str] = None,
    ) -> Dict[str, Path]:
        """Decision katmanına göre ayrılmış dataset dosyalarını JSONL olarak kaydet."""
        split = self.split_labeled_assets_by_decision(labeled_assets)
        instruction_text = instruction or DEFAULT_INSTRUCTION

        training_records = build_instruction_records(split["training"], instruction=instruction_text)
        review_records = build_instruction_records(split["review"], instruction=instruction_text)
        policy_drop_records = build_instruction_records(split.get("policy_drop", []), instruction=instruction_text)
        quality_reject_records = build_instruction_records(split.get("quality_reject", []), instruction=instruction_text)
        dropped_records = build_instruction_records(split["dropped"], instruction=instruction_text)

        output_paths = {
            "training": self.output_dir / "dataset_training.jsonl",
            "review": self.output_dir / "dataset_review.jsonl",
            "policy_drop": self.output_dir / "dataset_policy_drop.jsonl",
            "quality_reject": self.output_dir / "dataset_quality_reject.jsonl",
            "dropped": self.output_dir / "dataset_dropped.jsonl",
        }

        write_jsonl(training_records, str(output_paths["training"]))
        write_jsonl(review_records, str(output_paths["review"]))
        write_jsonl(policy_drop_records, str(output_paths["policy_drop"]))
        write_jsonl(quality_reject_records, str(output_paths["quality_reject"]))
        write_jsonl(dropped_records, str(output_paths["dropped"]))

        return output_paths
    
    def _infer_primitive_type(self, algo_name: str) -> PrimitiveType:
        """Algoritma adından ilkel türü çıkar"""
        algo_lower = algo_name.lower()
        
        if any(x in algo_lower for x in ["csprng", "random"]):
            return PrimitiveType.KEY_DERIVATION
        if any(x in algo_lower for x in ["pbkdf2", "bcrypt", "argon2", "scrypt", "kdf"]):
            return PrimitiveType.KEY_DERIVATION
        if any(x in algo_lower for x in ["cipher", "encrypt", "decrypt"]):
            return PrimitiveType.BLOCK_CIPHER
        if any(x in algo_lower for x in ["rsa", "ecc", "ecdsa", "ecdh"]):
            return PrimitiveType.ASYMMETRIC
        elif any(x in algo_lower for x in ["aes", "des", "rc4"]):
            return PrimitiveType.BLOCK_CIPHER
        elif any(x in algo_lower for x in ["sha", "md5", "blake"]):
            return PrimitiveType.HASH
        elif any(x in algo_lower for x in ["hmac"]):
            return PrimitiveType.HMAC
        elif any(x in algo_lower for x in ["gcm", "ccm", "chacha"]):
            return PrimitiveType.AUTHENTICATED_ENCRYPTION
        else:
            return PrimitiveType.HASH
    
    def _infer_functions(self, algo_name: str) -> List[CryptoFunction]:
        """Algoritma türünden olası fonksiyonları çıkar"""
        algo_lower = algo_name.lower()
        functions = []
        
        if any(x in algo_lower for x in ["csprng", "random"]):
            functions = [CryptoFunction.RANDOM_NUMBER_GENERATION]
        if any(x in algo_lower for x in ["pbkdf2", "bcrypt", "argon2", "scrypt", "kdf"]):
            functions = [CryptoFunction.KEY_DERIVATION]
        if any(x in algo_lower for x in ["aes", "des", "rc4"]):
            functions = [CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT]
        elif any(x in algo_lower for x in ["rsa", "ecc"]):
            functions = [CryptoFunction.KEY_GENERATION, CryptoFunction.KEY_AGREEMENT]
        elif any(x in algo_lower for x in ["sha", "md5", "blake"]):
            functions = [CryptoFunction.HASH]
        elif any(x in algo_lower for x in ["sign", "dsa", "ecdsa"]):
            functions = [CryptoFunction.SIGN, CryptoFunction.VERIFY]
        
        return functions if functions else [CryptoFunction.ENCRYPT]
    
    def _risk_level_from_score(self, score: float) -> str:
        """Risk puanından risk seviyesi oluştur"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"

    def _is_llm_candidate(self, cbom: CryptoBOM, static_results: Dict[str, Any], llm_min_confidence: float = 0.0) -> bool:
        """LLM'i sadece aday dosyalarda çalıştırmak için basit ve hızlı bir filtre."""
        if not cbom.crypto_assets:
            return False

        if llm_min_confidence <= 0.0:
            return True

        # Daha düşük güvenli veya generic bulgular LLM doğrulaması için adaydır.
        for asset in cbom.crypto_assets:
            algo = asset.algorithm.name.lower()
            if asset.confidence <= llm_min_confidence:
                return True
            if "generic" in algo or "unknown" in algo:
                return True

        # Ek koruma: çok sayıda sembol varsa bağlamsal LLM değerli olabilir.
        if len(static_results.get("symbols", [])) >= 8:
            return True

        return False

    def _llm_cache_key(self, snippet: str) -> str:
        payload = f"{self.llm_engine.config.provider}|{self.llm_engine.config.model}|{snippet}"
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()

    def _analyze_snippet_with_cache(self, snippet: str) -> AnalysisResult:
        if not self.llm_cache_enabled:
            return self.llm_engine.analyze_code_block(snippet)

        key = self._llm_cache_key(snippet)
        cached = self.llm_snippet_cache.get(key)
        if cached:
            return AnalysisResult(**cached)

        result = self.llm_engine.analyze_code_block(snippet)
        self.llm_snippet_cache[key] = asdict(result)
        return result
    
    def _enhance_with_llm(self, cbom: CryptoBOM, target: Path, max_snippets: int = 4):
        """LLM analizi ile CBOM'u zenginleştir"""
        try:
            with open(target, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # İçeriği parçalara böl
            max_size = 2000
            snippets = [content[i:i+max_size] for i in range(0, len(content), max_size)]
            
            # Her snippet'i analiz et
            for snippet in snippets[:max_snippets]:
                if len(snippet.strip()) < 50:
                    continue
                
                result = self._analyze_snippet_with_cache(snippet)
                
                if result.success and result.algorithm:
                    self._upsert_llm_asset(cbom, result, source="source-code")
        
        except Exception as e:
            print(f"LLM analiz hatası: {str(e)}")

    def _enhance_binary_with_llm(self, cbom: CryptoBOM, target: Path, static_results: Dict):
        """Binary için statik bulguları metin özetine çevirip LLM ile zenginleştir"""
        try:
            symbols = static_results.get("symbols", [])
            libraries = static_results.get("libraries", [])

            if not symbols and not libraries:
                return

            symbol_names = [s.get("name", "") for s in symbols if s.get("name")]
            # Aşırı uzun promptu engellemek için örnekleme yap
            unique_symbol_names = list(dict.fromkeys(symbol_names))[:120]
            unique_libraries = list(dict.fromkeys(libraries))[:40]

            summary_lines = [
                f"Binary file: {target.name}",
                f"Detected libraries: {', '.join(unique_libraries) if unique_libraries else 'none'}",
                "Detected symbol names:",
                ", ".join(unique_symbol_names) if unique_symbol_names else "none",
            ]

            snippet = "\n".join(summary_lines)
            result = self._analyze_snippet_with_cache(snippet)
            if result.success and result.algorithm:
                self._upsert_llm_asset(cbom, result, source="binary-llm")

        except Exception as e:
            print(f"Binary LLM analiz hatası: {str(e)}")

    def _upsert_llm_asset(self, cbom: CryptoBOM, result, source: str):
        """LLM sonucunu mevcut varlıkla birleştir veya yeni varlık ekle"""
        existing = next(
            (a for a in cbom.crypto_assets if a.algorithm.name == result.algorithm),
            None
        )

        if existing:
            existing.confidence = max(existing.confidence, result.confidence)
            if result.key_length:
                existing.algorithm.key_length = result.key_length
            if result.mode and not existing.algorithm.mode:
                existing.algorithm.mode = result.mode
            if result.is_pqc_safe:
                existing.algorithm.is_pqc_safe = True
            return

        new_asset = CryptoAsset(
            ref=f"crypto-{uuid.uuid4().hex[:8]}",
            algorithm=AlgorithmDetails(
                name=result.algorithm,
                type=self._infer_primitive_type(result.algorithm),
                key_length=result.key_length,
                mode=result.mode,
                is_pqc_safe=result.is_pqc_safe
            ),
            crypto_functions=self._infer_functions(result.algorithm),
            source=source,
            confidence=result.confidence
        )
        cbom.crypto_assets.append(new_asset)
    
    def _compute_summary(self, cbom: CryptoBOM):
        """CBOM için özet istatistikler hesapla"""
        if not cbom.crypto_assets:
            cbom.summary = {
                "total_algorithms": 0,
                "pqc_compliant": 0,
                "legacy_algorithms": 0,
                "average_risk": 0.0
            }
            cbom.risk_score = 0.0
            return
        
        total = len(cbom.crypto_assets)
        pqc_count = sum(1 for a in cbom.crypto_assets if a.algorithm.is_pqc_safe)
        legacy_count = sum(1 for a in cbom.crypto_assets if not a.algorithm.is_pqc_safe)
        
        # Risk skorları hesapla
        risks = []
        for asset in cbom.crypto_assets:
            risk = calculate_risk_score(asset.algorithm.name, asset.algorithm.key_length)
            risks.append(risk.final_risk)
        
        avg_risk = sum(risks) / len(risks) if risks else 0.0
        
        cbom.summary = {
            "total_algorithms": total,
            "pqc_compliant": pqc_count,
            "legacy_algorithms": legacy_count,
            "average_risk": round(avg_risk, 2),
            "algorithm_names": [a.algorithm.name for a in cbom.crypto_assets]
        }
        
        cbom.risk_score = min(avg_risk, 100.0)
    
    def save_cbom_json(self, cbom: CryptoBOM, filename: Optional[str] = None) -> Path:
        """
        CBOM'u JSON dosyasına kaydet
        
        Args:
            cbom: CBOM nesnesi
            filename: Dosya adı (isteğe bağlı)
            
        Returns:
            Kaydedilen dosya yolu
        """
        if filename is None:
            filename = f"cbom_{cbom.bom_ref}.json"
        
        output_file = self.output_dir / filename
        
        # Datetime'ı serialize et
        cbom_dict = json.loads(cbom.model_dump_json())
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cbom_dict, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def get_risk_recommendations(self, cbom: CryptoBOM) -> Dict[str, Any]:
        """
        CBOM'dan risk tavsiyelerini derle
        
        Args:
            cbom: CBOM nesnesi
            
        Returns:
            Tavsiyeler sözlüğü
        """
        recommendations = {
            "overall_score": cbom.risk_score,
            "critical_issues": [],
            "high_priority": [],
            "medium_priority": [],
            "low_priority": []
        }
        
        for asset in cbom.crypto_assets:
            risk = calculate_risk_score(asset.algorithm.name, asset.algorithm.key_length)
            
            recommendation = {
                "algorithm": asset.algorithm.name,
                "current_risk": risk.final_risk,
                "recommendation": risk.recommendation,
                "mitigation": risk.mitigation
            }
            
            if risk.final_risk >= 80:
                recommendations["critical_issues"].append(recommendation)
            elif risk.final_risk >= 60:
                recommendations["high_priority"].append(recommendation)
            elif risk.final_risk >= 40:
                recommendations["medium_priority"].append(recommendation)
            else:
                recommendations["low_priority"].append(recommendation)
        
        return recommendations
    
    def generate_report(self, cbom: CryptoBOM) -> Dict[str, Any]:
        """
        Kapsamlı bir rapor oluştur
        
        Args:
            cbom: CBOM nesnesi
            
        Returns:
            Rapor sözlüğü
        """
        recommendations = self.get_risk_recommendations(cbom)
        
        # İstatistikler
        stats = {
            "scan_date": cbom.created.isoformat(),
            "target_file": cbom.target_file,
            "target_type": cbom.target_type,
            "total_crypto_components": len(cbom.crypto_assets),
            "pqc_ready": sum(1 for a in cbom.crypto_assets if a.algorithm.is_pqc_safe),
            "not_pqc_ready": sum(1 for a in cbom.crypto_assets if not a.algorithm.is_pqc_safe),
            "overall_risk_score": cbom.risk_score
        }
        
        return {
            "summary": cbom.summary,
            "statistics": stats,
            "recommendations": recommendations,
            "assets": [json.loads(a.model_dump_json()) for a in cbom.crypto_assets]
        }


# CLI Test
if __name__ == "__main__":
    import sys
    import re
    
    # Kullanım: python main.py <file_path>
    if len(sys.argv) > 1:
        target = sys.argv[1]

        target_name = Path(target).name
        safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "-", target_name).strip("-._") or "target"
        run_dir = Path("output") / f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{safe_target}"
        analyzer = PQCReadyAnalyzer(output_dir=str(run_dir))
        
        print(f"Analiz ediliyor: {target}")
        try:
            cbom = analyzer.analyze_target(target, use_llm=False)
            
            # CBOM'u kaydet
            output_file = analyzer.save_cbom_json(cbom)
            print(f"CBOM kaydedildi: {output_file}")
            
            # Raporu yazdır
            report = analyzer.generate_report(cbom)
            print("\n=== ANALIZ RAPORU ===")
            print(json.dumps(report, indent=2, ensure_ascii=False))
            
        except Exception as e:
            print(f"Hata: {str(e)}")
    else:
        print("Kullanım: python main.py <file_path>")
        print("Örnek: python main.py /path/to/binary")

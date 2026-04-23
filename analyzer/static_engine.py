"""
Statik Analiz Engine - Binary & Kütüphane Tespiti
ELF/PE binaries'deki kriptografik fonksiyonları tespit eder
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

try:
    import elftools
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class SymbolMatch:
    """Bulunan sembol eşleşmesi"""
    symbol_name: str
    library: str
    algorithm: str
    confidence: float


# Kriptografik Fonksiyon Mapping
CRYPTO_FUNCTION_MAPPING = {
    # OpenSSL/LibCrypto - RSA
    "RSA_generate_key": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.95},
    "RSA_new": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.85},
    "RSA_public_encrypt": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.9},
    "RSA_private_decrypt": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.9},
    "RSA_sign": {"algorithm": "RSA", "type": "signing", "confidence": 0.9},
    "RSA_verify": {"algorithm": "RSA", "type": "signing", "confidence": 0.9},
    
    # OpenSSL/LibCrypto - AES
    "AES_encrypt": {"algorithm": "AES", "type": "block-cipher", "confidence": 0.95},
    "AES_decrypt": {"algorithm": "AES", "type": "block-cipher", "confidence": 0.95},
    "AES_set_encrypt_key": {"algorithm": "AES", "type": "block-cipher", "confidence": 0.9},
    "AES_set_decrypt_key": {"algorithm": "AES", "type": "block-cipher", "confidence": 0.9},
    
    # OpenSSL - EVP (high-level interface)
    "EVP_aes_256_cbc": {"algorithm": "AES-256-CBC", "type": "block-cipher", "confidence": 0.95},
    "EVP_aes_128_cbc": {"algorithm": "AES-128-CBC", "type": "block-cipher", "confidence": 0.95},
    "EVP_aes_256_gcm": {"algorithm": "AES-256-GCM", "type": "authenticated-encryption", "confidence": 0.95},
    "EVP_aes_128_gcm": {"algorithm": "AES-128-GCM", "type": "authenticated-encryption", "confidence": 0.95},
    "EVP_EncryptInit_ex": {"algorithm": "generic-cipher", "type": "encryption", "confidence": 0.7},
    "EVP_DecryptInit_ex": {"algorithm": "generic-cipher", "type": "decryption", "confidence": 0.7},
    "EVP_Cipher": {"algorithm": "generic-cipher", "type": "encryption", "confidence": 0.65},
    
    # OpenSSL - Hash/Digest
    "SHA_Init": {"algorithm": "SHA-1", "type": "hash", "confidence": 0.9},
    "SHA1_Init": {"algorithm": "SHA-1", "type": "hash", "confidence": 0.95},
    "SHA256_Init": {"algorithm": "SHA-256", "type": "hash", "confidence": 0.95},
    "SHA512_Init": {"algorithm": "SHA-512", "type": "hash", "confidence": 0.95},
    "MD5_Init": {"algorithm": "MD5", "type": "hash", "confidence": 0.95},
    "EVP_md5": {"algorithm": "MD5", "type": "hash", "confidence": 0.9},
    "EVP_sha1": {"algorithm": "SHA-1", "type": "hash", "confidence": 0.9},
    "EVP_sha256": {"algorithm": "SHA-256", "type": "hash", "confidence": 0.95},
    "EVP_sha512": {"algorithm": "SHA-512", "type": "hash", "confidence": 0.95},
    "EVP_DigestSign": {"algorithm": "generic-sign", "type": "signing", "confidence": 0.8},
    "EVP_DigestVerify": {"algorithm": "generic-verify", "type": "verification", "confidence": 0.8},
    
    # OpenSSL - HMAC
    "HMAC_Init": {"algorithm": "HMAC", "type": "hmac", "confidence": 0.9},
    "HMAC_Update": {"algorithm": "HMAC", "type": "hmac", "confidence": 0.85},
    "HMAC_Final": {"algorithm": "HMAC", "type": "hmac", "confidence": 0.85},
    
    # OpenSSL - ECC/ECDSA
    "EC_KEY_new": {"algorithm": "ECC", "type": "asymmetric", "confidence": 0.85},
    "EC_KEY_generate_key": {"algorithm": "ECC", "type": "asymmetric", "confidence": 0.9},
    "ECDSA_sign": {"algorithm": "ECDSA", "type": "signing", "confidence": 0.95},
    "ECDSA_verify": {"algorithm": "ECDSA", "type": "verification", "confidence": 0.95},
    "ECDH_compute_key": {"algorithm": "ECDH", "type": "key-exchange", "confidence": 0.95},
    
    # WolfSSL
    "wc_Aes_CbcEncrypt": {"algorithm": "AES-CBC", "type": "block-cipher", "confidence": 0.95},
    "wc_Aes_CbcDecrypt": {"algorithm": "AES-CBC", "type": "block-cipher", "confidence": 0.95},
    "wc_Aes_GcmEncrypt": {"algorithm": "AES-GCM", "type": "authenticated-encryption", "confidence": 0.95},
    "wc_Aes_GcmDecrypt": {"algorithm": "AES-GCM", "type": "authenticated-encryption", "confidence": 0.95},
    "wc_Sha256Hash": {"algorithm": "SHA-256", "type": "hash", "confidence": 0.95},
    "wc_Sha512Hash": {"algorithm": "SHA-512", "type": "hash", "confidence": 0.95},
    "wc_RsaEncrypt": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.95},
    "wc_RsaDecrypt": {"algorithm": "RSA", "type": "asymmetric", "confidence": 0.95},
    "wc_ecc_make_key": {"algorithm": "ECC", "type": "asymmetric", "confidence": 0.95},
    
    # BoringSSL / Google
    "AEAD_AES_256_GCM": {"algorithm": "AES-256-GCM", "type": "authenticated-encryption", "confidence": 0.9},
    "SHA256": {"algorithm": "SHA-256", "type": "hash", "confidence": 0.85},
    
    # Generic patterns
    "crypt": {"algorithm": "generic-cipher", "type": "encryption", "confidence": 0.5},
    "decrypt": {"algorithm": "generic-cipher", "type": "decryption", "confidence": 0.5},
    "hash": {"algorithm": "generic-hash", "type": "hash", "confidence": 0.5},
    "sign": {"algorithm": "generic-sign", "type": "signing", "confidence": 0.6},
    "hmac": {"algorithm": "HMAC", "type": "hmac", "confidence": 0.7},

    # Windows CNG / BCrypt
    "BCryptEncrypt": {"algorithm": "generic-cipher", "type": "encryption", "confidence": 0.8},
    "BCryptDecrypt": {"algorithm": "generic-cipher", "type": "decryption", "confidence": 0.8},
    "BCryptGenerateSymmetricKey": {"algorithm": "AES", "type": "block-cipher", "confidence": 0.75},
    "BCryptGenRandom": {"algorithm": "CSPRNG", "type": "random", "confidence": 0.85},
    "BCryptHashData": {"algorithm": "generic-hash", "type": "hash", "confidence": 0.8},
    "BCryptFinishHash": {"algorithm": "generic-hash", "type": "hash", "confidence": 0.8},
    "BCryptSignHash": {"algorithm": "generic-sign", "type": "signing", "confidence": 0.8},
    "BCryptVerifySignature": {"algorithm": "generic-verify", "type": "verification", "confidence": 0.8},
}


SYMBOL_PREFIX_MAPPING = {
    "BCrypt": {"algorithm": "generic-cipher", "type": "encryption", "confidence": 0.65},
    "NCrypt": {"algorithm": "generic-asymmetric", "type": "asymmetric", "confidence": 0.65},
}

LIBRARY_PATTERNS = {
    "libcrypto": "OpenSSL",
    "libssl": "OpenSSL",
    "wolfssl": "WolfSSL",
    "libressl": "LibreSSL",
    "nettle": "Nettle",
    "gnutls": "GnuTLS",
    "mbedtls": "MbedTLS",
    "sodium": "libsodium",
    "gcrypt": "libgcrypt",
    "boringssl": "BoringSSL",
}


SOURCE_CODE_PATTERNS = [
    # Python cryptography / hashlib patterns
    (r"\brsa\.generate_private_key\s*\(", "RSA", "asymmetric", 0.95),
    (r"\brsa\.generate\s*\(", "RSA", "asymmetric", 0.85),
    (r"\bhashlib\.sha1\s*\(", "SHA-1", "hash", 0.95),
    (r"\bhashlib\.sha256\s*\(", "SHA-256", "hash", 0.95),
    (r"\bhashlib\.sha512\s*\(", "SHA-512", "hash", 0.95),
    (r"\bhashlib\.md5\s*\(", "MD5", "hash", 0.95),
    (r"\balgorithms\.aes\s*\(", "AES", "block-cipher", 0.9),
    (r"\bCipher\s*\(", "generic-cipher", "encryption", 0.7),
    (r"\bpadding\.PKCS7\b", "generic-cipher", "encryption", 0.6),
    (r"\bec\.generate_private_key\s*\(", "ECC", "asymmetric", 0.85),
    (r"\bec\.[A-Z0-9_]+\b", "ECC", "asymmetric", 0.75),
    # Common C/OpenSSL source patterns
    (r"\bRSA_generate_key\s*\(", "RSA", "asymmetric", 0.95),
    (r"\bAES_encrypt\s*\(", "AES", "block-cipher", 0.95),
    (r"\bEVP_DigestSign\b", "generic-sign", "signing", 0.8),
    (r"\bEVP_DigestVerify\b", "generic-verify", "verification", 0.8),
]


class StaticAnalysisEngine:
    """Statik Analiz Motoru"""
    
    def __init__(self):
        self.found_symbols: List[SymbolMatch] = []
        self.detected_libraries: List[str] = []
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Dosyayı analiz et ve kriptografik fonksiyonları tespit et
        
        Args:
            file_path: Analiz edilecek dosya yolu
            
        Returns:
            Bulunan kriptografik varlıklar sözlüğü
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")
        
        results = {
            "file": str(file_path),
            "file_type": self._detect_file_type(file_path),
            "symbols": [],
            "libraries": [],
            "crypto_assets": {}
        }
        
        # Dosya türüne göre analiz
        if results["file_type"] == "ELF":
            self._analyze_elf(file_path, results)
        elif results["file_type"] == "PE":
            self._analyze_pe(file_path, results)
        elif results["file_type"] == "TEXT":
            self._analyze_source_code(file_path, results)
        
        # Bulunan sembollerden kripto varlıkları derle
        self._compile_crypto_assets(results)
        
        return results
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Dosya türünü tespit et"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
        except:
            return "UNKNOWN"
        
        # ELF magic number
        if magic == b'\x7fELF':
            return "ELF"
        # PE/DOS magic number
        elif magic[:2] == b'MZ':
            return "PE"
        # Metin dosyası (Python, C, vb.)
        else:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(100)
                return "TEXT"
            except:
                return "BINARY"
    
    def _analyze_elf(self, file_path: Path, results: Dict):
        """ELF binary dosyasını analiz et"""
        if not HAS_ELFTOOLS:
            results["error"] = "elftools kütüphanesi yüklü değil (pip install pyelftools)"
            return
        
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection
            
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Dinamik kütüphaneleri bul
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                lib = tag.needed
                                results["libraries"].append(lib)
                                self._detect_library_type(lib)
                
                # Symbol table'dan sembolleri çıkar
                symtab = elf.get_section_by_name('.symtab')
                if not symtab:
                    symtab = elf.get_section_by_name('.dynsym')
                
                if symtab:
                    for symbol in symtab.iter_symbols():
                        if symbol.name in CRYPTO_FUNCTION_MAPPING:
                            match = SymbolMatch(
                                symbol_name=symbol.name,
                                library="linked",
                                algorithm=CRYPTO_FUNCTION_MAPPING[symbol.name]["algorithm"],
                                confidence=CRYPTO_FUNCTION_MAPPING[symbol.name]["confidence"]
                            )
                            self.found_symbols.append(match)
                            results["symbols"].append({
                                "name": symbol.name,
                                "algorithm": match.algorithm,
                                "confidence": match.confidence
                            })
        except Exception as e:
            results["error"] = f"ELF analiz hatası: {str(e)}"
    
    def _analyze_pe(self, file_path: Path, results: Dict):
        """PE binary dosyasını analiz et (Windows)"""
        if not HAS_PEFILE:
            results["error"] = "pefile kütüphanesi yüklü değil (pip install pefile)"
            return
        
        try:
            pe = pefile.PE(str(file_path))
            
            # Import table'dan kütüphaneleri çıkar
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    results["libraries"].append(dll)
                    self._detect_library_type(dll)
                    
                    # DLL'deki fonksiyonları kontrol et
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else ""
                        mapping = self._match_crypto_symbol(func_name)
                        if mapping:
                            match = SymbolMatch(
                                symbol_name=func_name,
                                library=dll,
                                algorithm=mapping["algorithm"],
                                confidence=mapping["confidence"]
                            )
                            self.found_symbols.append(match)
                            results["symbols"].append({
                                "name": func_name,
                                "library": dll,
                                "algorithm": match.algorithm,
                                "confidence": match.confidence
                            })

            # Export table'dan sembolleri de tarayarak DLL dosyalarını doğrudan analiz et
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
                for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not symbol.name:
                        continue
                    func_name = symbol.name.decode('utf-8', errors='ignore')
                    mapping = self._match_crypto_symbol(func_name)
                    if mapping:
                        match = SymbolMatch(
                            symbol_name=func_name,
                            library=file_path.name,
                            algorithm=mapping["algorithm"],
                            confidence=mapping["confidence"]
                        )
                        self.found_symbols.append(match)
                        results["symbols"].append({
                            "name": func_name,
                            "library": file_path.name,
                            "algorithm": match.algorithm,
                            "confidence": match.confidence
                        })
        except Exception as e:
            results["error"] = f"PE analiz hatası: {str(e)}"

    def _match_crypto_symbol(self, func_name: str) -> Optional[Dict]:
        """Fonksiyon adını doğrudan veya önek bazlı kripto eşleşmesiyle bul"""
        if not func_name:
            return None

        if func_name in CRYPTO_FUNCTION_MAPPING:
            return CRYPTO_FUNCTION_MAPPING[func_name]

        for prefix, mapping in SYMBOL_PREFIX_MAPPING.items():
            if func_name.startswith(prefix):
                return mapping

        return None
    
    def _analyze_source_code(self, file_path: Path, results: Dict):
        """Kaynak kodu (Python, C, vb.) analiz et"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            seen_symbols = set()

            # Dil-bağımsız özel kalıplar
            for pattern, algorithm, primitive_type, confidence in SOURCE_CODE_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    symbol_key = (algorithm, line_num)
                    if symbol_key in seen_symbols:
                        continue
                    seen_symbols.add(symbol_key)
                    results["symbols"].append({
                        "name": algorithm,
                        "algorithm": algorithm,
                        "line": line_num,
                        "confidence": confidence,
                        "primitive_type": primitive_type,
                    })

                    self.found_symbols.append(
                        SymbolMatch(
                            symbol_name=algorithm,
                            library="source-code",
                            algorithm=algorithm,
                            confidence=confidence,
                        )
                    )
            
            # Regex'ler ile kriptografik fonksiyon çağrılarını bul
            for func_name in CRYPTO_FUNCTION_MAPPING.keys():
                if func_name in {"crypt", "decrypt", "hash", "sign", "hmac"}:
                    continue

                # Çeşitli eşleştirme desenleri
                patterns = [
                    rf'\b{func_name}\s*\(',  # Fonksiyon çağrısı
                ]
                
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        symbol_key = (func_name, line_num)
                        if symbol_key in seen_symbols:
                            continue
                        seen_symbols.add(symbol_key)
                        results["symbols"].append({
                            "name": func_name,
                            "algorithm": CRYPTO_FUNCTION_MAPPING[func_name]["algorithm"],
                            "line": line_num,
                            "confidence": CRYPTO_FUNCTION_MAPPING[func_name]["confidence"]
                        })
                        
                        match_obj = SymbolMatch(
                            symbol_name=func_name,
                            library="source-code",
                            algorithm=CRYPTO_FUNCTION_MAPPING[func_name]["algorithm"],
                            confidence=CRYPTO_FUNCTION_MAPPING[func_name]["confidence"]
                        )
                        self.found_symbols.append(match_obj)
        except Exception as e:
            results["error"] = f"Kaynak kod analiz hatası: {str(e)}"
    
    def _detect_library_type(self, lib_name: str):
        """Kütüphane türünü tespit et"""
        lib_lower = lib_name.lower()
        for pattern, lib_type in LIBRARY_PATTERNS.items():
            if pattern in lib_lower:
                if lib_type not in self.detected_libraries:
                    self.detected_libraries.append(lib_type)
    
    def _compile_crypto_assets(self, results: Dict):
        """Bulunan sembollerden kripto varlıkları derle"""
        assets = {}
        
        for symbol in results["symbols"]:
            algo = symbol["algorithm"]
            if algo not in assets:
                assets[algo] = {
                    "algorithm": algo,
                    "occurrences": 0,
                    "confidence": 0.0,
                    "locations": []
                }
            
            assets[algo]["occurrences"] += 1
            assets[algo]["confidence"] = max(assets[algo]["confidence"], symbol.get("confidence", 0.5))
            
            if "line" in symbol:
                assets[algo]["locations"].append(f"Line {symbol['line']}")
        
        results["crypto_assets"] = assets
        results["detected_libraries"] = self.detected_libraries
    
    def get_summary(self, results: Dict) -> Dict:
        """Analiz sonuçlarının özetini döndür"""
        return {
            "total_crypto_functions": len(results["symbols"]),
            "unique_algorithms": len(results["crypto_assets"]),
            "detected_libraries": results.get("detected_libraries", []),
            "algorithms": list(results["crypto_assets"].keys())
        }


# CLI test
if __name__ == "__main__":
    import json
    
    engine = StaticAnalysisEngine()
    
    # Test dosyası
    test_file = "test_binary"
    if os.path.exists(test_file):
        results = engine.analyze_file(test_file)
        print(json.dumps(results, indent=2, default=str))
        print("\nÖZET:")
        print(json.dumps(engine.get_summary(results), indent=2))
    else:
        print("Test dosyası bulunamadı. Analiz için bir dosya sağla.")
        print("\nÖrnek kullanım:")
        print("  engine = StaticAnalysisEngine()")
        print("  results = engine.analyze_file('/path/to/binary')")

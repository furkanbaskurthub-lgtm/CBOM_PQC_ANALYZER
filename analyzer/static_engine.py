"""
Statik Analiz Engine - Binary & Kütüphane Tespiti
ELF/PE binaries'deki kriptografik fonksiyonları tespit eder
"""

import os
import re
import ast
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Set
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
    # OpenSSL - SSL/TLS and related helpers (QuickFIX relevance)
    "SSL_library_init": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_load_error_strings": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.85},
    "SSL_CTX_new": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.92},
    "SSL_CTX_free": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_new": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_free": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_connect": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_accept": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "SSL_read": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.88},
    "SSL_write": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.88},
    "SSL_CTX_use_certificate_file": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.92},
    "SSL_CTX_use_PrivateKey_file": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.92},
    "SSL_CTX_use_PrivateKey": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "PEM_read_bio_PrivateKey": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "PEM_read_bio_X509": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "PEM_read_X509": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.9},
    "BIO_new": {"algorithm": "TLS/SSL", "type": "tls-helper", "confidence": 0.7},
    "BIO_free": {"algorithm": "TLS/SSL", "type": "tls-helper", "confidence": 0.7},
    "RAND_seed": {"algorithm": "CSPRNG", "type": "random", "confidence": 0.85},
    "DH_generate_parameters": {"algorithm": "DH", "type": "key-exchange", "confidence": 0.9},
    "SSL_CTX_set_cipher_list": {"algorithm": "TLS/SSL", "type": "tls", "confidence": 0.85},
    
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
    # Keep ECC attribute matching narrow to avoid SQL alias false positives like `ec.id`.
    (r"\bec\.(SECP\d+R1|SECP\d+K1|BRAINPOOLP\d+R1|ECDSA|ECDH)\b", "ECC", "asymmetric", 0.9),
    # Common C/OpenSSL source patterns
    (r"\bRSA_generate_key\s*\(", "RSA", "asymmetric", 0.95),
    (r"\bAES_encrypt\s*\(", "AES", "block-cipher", 0.95),
    (r"\bEVP_DigestSign\b", "generic-sign", "signing", 0.8),
    (r"\bEVP_DigestVerify\b", "generic-verify", "verification", 0.8),
    # OpenSSL includes and QuickFIX SSL helper patterns
    (r"#\s*include\s*<openssl/ssl.h>", "TLS/SSL", "tls", 0.98),
    (r"#\s*include\s*<openssl/err.h>", "TLS/SSL", "tls", 0.9),
    (r"#\s*include\s*<openssl/pem.h>", "TLS/SSL", "tls", 0.9),
    (r"#\s*include\s*\"UtilitySSL\.h\"", "TLS/SSL", "tls", 0.9),
    (r"\bSSL_library_init\s*\(", "TLS/SSL", "tls", 0.9),
    (r"\bSSL_CTX_new\s*\(", "TLS/SSL", "tls", 0.92),
    (r"\bSSL_CTX_use_PrivateKey\s*\(", "TLS/SSL", "tls", 0.92),
    (r"\bSSL_CTX_use_certificate_file\s*\(", "TLS/SSL", "tls", 0.92),
    (r"\bPEM_read_\w+\s*\(", "TLS/SSL", "tls", 0.88),
    (r"\bBIO_new\s*\(", "TLS/SSL", "tls-helper", 0.7),
    (r"\bRAND_seed\s*\(", "CSPRNG", "random", 0.85),
    # Java/JCA patterns (Fineract-like codebases)
    (r"\bCipher\.getInstance\s*\(\s*\"AES/GCM/NoPadding\"", "AES-GCM", "authenticated-encryption", 0.97),
    (r"\bCipher\.getInstance\s*\(\s*\"AES/CBC/PKCS5Padding\"", "AES-CBC", "block-cipher", 0.96),
    (r"\bCipher\.getInstance\s*\(\s*\"AES/CTR/NoPadding\"", "AES-CTR", "block-cipher", 0.95),
    (r"\bCipher\.getInstance\s*\(\s*\"RSA/ECB/OAEP", "RSA-OAEP", "asymmetric", 0.96),
    (r"\bCipher\.getInstance\s*\(\s*\"RSA/ECB/PKCS1Padding\"", "RSA", "asymmetric", 0.93),
    (r"\bCipher\.getInstance\s*\(", "generic-cipher", "encryption", 0.75),
    (r"\bMessageDigest\.getInstance\s*\(\s*\"SHA-256\"", "SHA-256", "hash", 0.97),
    (r"\bMessageDigest\.getInstance\s*\(\s*\"SHA-512\"", "SHA-512", "hash", 0.97),
    (r"\bMessageDigest\.getInstance\s*\(\s*\"SHA-1\"", "SHA-1", "hash", 0.95),
    (r"\bMessageDigest\.getInstance\s*\(\s*\"MD5\"", "MD5", "hash", 0.95),
    (r"\bMac\.getInstance\s*\(\s*\"HmacSHA256\"", "HMAC-SHA256", "hmac", 0.97),
    (r"\bMac\.getInstance\s*\(\s*\"HmacSHA512\"", "HMAC-SHA512", "hmac", 0.97),
    (r"\bSignature\.getInstance\s*\(\s*\"SHA256withRSA\"", "RSA", "signing", 0.96),
    (r"\bSignature\.getInstance\s*\(\s*\"SHA512withRSA\"", "RSA", "signing", 0.96),
    (r"\bSignature\.getInstance\s*\(\s*\"SHA256withECDSA\"", "ECDSA", "signing", 0.96),
    (r"\bSignature\.getInstance\s*\(\s*\"Ed25519\"", "Ed25519", "signing", 0.96),
    (r"\bKeyPairGenerator\.getInstance\s*\(\s*\"RSA\"", "RSA", "asymmetric", 0.95),
    (r"\bKeyPairGenerator\.getInstance\s*\(\s*\"EC\"", "ECC", "asymmetric", 0.95),
    (r"\bKeyAgreement\.getInstance\s*\(\s*\"ECDH\"", "ECDH", "key-exchange", 0.98),
    (r"\bKeyAgreement\.getInstance\s*\(\s*\"DH\"", "DH", "key-exchange", 0.98),
    (r"\bSecretKeyFactory\.getInstance\s*\(\s*\"PBKDF2WithHmacSHA256\"", "PBKDF2-HMAC-SHA256", "password-hash", 0.97),
    (r"\bSecretKeyFactory\.getInstance\s*\(\s*\"PBKDF2WithHmacSHA512\"", "PBKDF2-HMAC-SHA512", "password-hash", 0.97),
    (r"\bBCryptPasswordEncoder\b", "bcrypt", "password-hash", 0.96),
    (r"\bArgon2PasswordEncoder\b", "argon2", "password-hash", 0.96),
    (r"\bPbkdf2PasswordEncoder\b", "PBKDF2", "password-hash", 0.94),
    (r"\bJwts\.builder\s*\(", "JWT-HMAC-or-Signature", "signing", 0.82),
    (r"\bJwtParserBuilder\b", "JWT-HMAC-or-Signature", "verification", 0.82),
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
            "crypto_assets": {},
            "evidence": []
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
                            results["evidence"].append({
                                "file_path": str(file_path),
                                "detector": "elf_symbol",
                                "source_type": "binary",
                                "algorithm": match.algorithm,
                                "snippet": symbol.name,
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
                            results["evidence"].append({
                                "file_path": str(file_path),
                                "detector": "pe_import",
                                "source_type": "binary",
                                "algorithm": match.algorithm,
                                "snippet": f"{dll}!{func_name}",
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
                        results["evidence"].append({
                            "file_path": str(file_path),
                            "detector": "pe_export",
                            "source_type": "binary",
                            "algorithm": match.algorithm,
                            "snippet": func_name,
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
            content = ""
            for enc in ("utf-8", "utf-8-sig", "latin-1"):
                try:
                    with open(file_path, 'r', encoding=enc) as f:
                        content = f.read()
                    break
                except Exception:
                    continue
            if not content:
                raise ValueError("source_file_read_failed")

            lines = content.splitlines()
            function_ranges = self._extract_python_function_ranges(content, file_path)

            seen_symbols = set()
            specific_lines: Set[int] = set()

            # Java JCA/JCE çağrılarını argüman çözümlemesiyle yakala (literal + String constants).
            if file_path.suffix.lower() == ".java":
                for item in self._detect_java_import_signals(content, lines):
                    line_num = item["line"]
                    symbol_key = (item["algorithm"], line_num)
                    if symbol_key in seen_symbols:
                        continue
                    seen_symbols.add(symbol_key)

                    results["symbols"].append({
                        "name": item["algorithm"],
                        "algorithm": item["algorithm"],
                        "line": line_num,
                        "confidence": item["confidence"],
                        "primitive_type": item["primitive_type"],
                    })
                    results["evidence"].append({
                        "file_path": str(file_path),
                        "line_start": line_num,
                        "line_end": line_num,
                        "function_name": self._resolve_function_name(line_num, function_ranges),
                        "snippet": item["snippet"],
                        "context_before": item["context_before"],
                        "context_after": item["context_after"],
                        "detector": "java_import_signal",
                        "source_type": "source",
                        "algorithm": item["algorithm"],
                    })

                    self.found_symbols.append(
                        SymbolMatch(
                            symbol_name=item["algorithm"],
                            library="source-code",
                            algorithm=item["algorithm"],
                            confidence=item["confidence"],
                        )
                    )

                for item in self._detect_java_jca_calls(content, lines):
                    line_num = item["line"]
                    symbol_key = (item["algorithm"], line_num)
                    if symbol_key in seen_symbols:
                        continue
                    seen_symbols.add(symbol_key)

                    if item["algorithm"] != "generic-cipher":
                        specific_lines.add(line_num)

                    results["symbols"].append({
                        "name": item["algorithm"],
                        "algorithm": item["algorithm"],
                        "line": line_num,
                        "confidence": item["confidence"],
                        "primitive_type": item["primitive_type"],
                    })
                    results["evidence"].append({
                        "file_path": str(file_path),
                        "line_start": line_num,
                        "line_end": line_num,
                        "function_name": self._resolve_function_name(line_num, function_ranges),
                        "snippet": item["snippet"],
                        "context_before": item["context_before"],
                        "context_after": item["context_after"],
                        "detector": "java_jca_resolver",
                        "source_type": "source",
                        "algorithm": item["algorithm"],
                    })

                    self.found_symbols.append(
                        SymbolMatch(
                            symbol_name=item["algorithm"],
                            library="source-code",
                            algorithm=item["algorithm"],
                            confidence=item["confidence"],
                        )
                    )

            # Dil-bağımsız özel kalıplar
            for pattern, algorithm, primitive_type, confidence in SOURCE_CODE_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    snippet, context_before, context_after = self._extract_context_lines(lines, line_num)

                    # Suppress SQL context noise (e.g., SELECT ... ec.id ...) from crypto labels.
                    snippet_lower = snippet.lower()
                    if algorithm == "ECC" and "ec." in snippet_lower:
                        if any(token in snippet_lower for token in ["select ", " from ", " join ", " where ", "insert ", "update "]):
                            continue

                    # Explicit Java transformations should prefer specific labels over generic-cipher.
                    if algorithm == "generic-cipher" and "Cipher.getInstance" in snippet:
                        if line_num in specific_lines:
                            continue
                        upper_snippet = snippet.upper()
                        if any(token in upper_snippet for token in ["AES/", "RSA/", "CHACHA20", "DES/"]):
                            continue

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
                    results["evidence"].append({
                        "file_path": str(file_path),
                        "line_start": line_num,
                        "line_end": line_num,
                        "function_name": self._resolve_function_name(line_num, function_ranges),
                        "snippet": snippet,
                        "context_before": context_before,
                        "context_after": context_after,
                        "detector": "source_pattern",
                        "source_type": "source",
                        "algorithm": algorithm,
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
                        snippet, context_before, context_after = self._extract_context_lines(lines, line_num)
                        results["evidence"].append({
                            "file_path": str(file_path),
                            "line_start": line_num,
                            "line_end": line_num,
                            "function_name": self._resolve_function_name(line_num, function_ranges),
                            "snippet": snippet,
                            "context_before": context_before,
                            "context_after": context_after,
                            "detector": "source_symbol",
                            "source_type": "source",
                            "algorithm": CRYPTO_FUNCTION_MAPPING[func_name]["algorithm"],
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

    def _extract_java_string_constants(self, content: str) -> Dict[str, str]:
        """Java String sabitlerini (özellikle algoritma/mode constant'larını) çıkar."""
        constants: Dict[str, str] = {}
        pattern = re.compile(
            r'\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?String\s+([A-Za-z_]\w*)\s*=\s*"([^"]+)"',
            re.IGNORECASE,
        )
        for m in pattern.finditer(content):
            constants[m.group(1)] = m.group(2)
        return constants

    def _classify_java_getinstance(self, api_name: str, arg_value: str) -> Tuple[str, str, float]:
        """JCA/JCE getInstance argümanını algoritma tipine eşle."""
        upper = (arg_value or "").upper()

        if api_name == "Cipher":
            if "AES/GCM" in upper:
                return "AES-GCM", "authenticated-encryption", 0.97
            if "AES/CBC" in upper:
                return "AES-CBC", "block-cipher", 0.96
            if "AES/CTR" in upper:
                return "AES-CTR", "block-cipher", 0.95
            if upper.startswith("AES"):
                return "AES", "block-cipher", 0.9
            if upper.startswith("RSA") and "OAEP" in upper:
                return "RSA-OAEP", "asymmetric", 0.96
            if upper.startswith("RSA"):
                return "RSA", "asymmetric", 0.93
            if "CHACHA20" in upper:
                return "ChaCha20", "stream-cipher", 0.92
            if any(x in upper for x in ["DES", "DESEDE", "TRIPLEDES"]):
                return "3DES", "block-cipher", 0.88
            return "generic-cipher", "encryption", 0.75

        if api_name == "MessageDigest":
            if "SHA-256" in upper:
                return "SHA-256", "hash", 0.97
            if "SHA-512" in upper:
                return "SHA-512", "hash", 0.97
            if "SHA-1" in upper:
                return "SHA-1", "hash", 0.95
            if "MD5" in upper:
                return "MD5", "hash", 0.95
            return "generic-hash", "hash", 0.75

        if api_name == "Mac":
            if "HMACSHA256" in upper:
                return "HMAC-SHA256", "hmac", 0.97
            if "HMACSHA512" in upper:
                return "HMAC-SHA512", "hmac", 0.97
            return "HMAC", "hmac", 0.8

        if api_name == "Signature":
            if "ED25519" in upper:
                return "Ed25519", "signing", 0.96
            if "ECDSA" in upper:
                return "ECDSA", "signing", 0.96
            if "RSA" in upper:
                return "RSA", "signing", 0.96
            return "generic-sign", "signing", 0.8

        if api_name == "KeyPairGenerator":
            if upper == "EC":
                return "ECC", "asymmetric", 0.95
            if upper == "RSA":
                return "RSA", "asymmetric", 0.95
            return "generic-asymmetric", "asymmetric", 0.8

        if api_name == "KeyAgreement":
            if upper == "ECDH":
                return "ECDH", "key-exchange", 0.98
            if upper == "DH":
                return "DH", "key-exchange", 0.98
            return "generic-key-exchange", "key-exchange", 0.8

        if api_name == "SecretKeyFactory":
            if "PBKDF2WITHHMACSHA1" in upper:
                return "PBKDF2-HMAC-SHA1", "password-hash", 0.95
            if "PBKDF2WITHHMACSHA256" in upper:
                return "PBKDF2-HMAC-SHA256", "password-hash", 0.97
            if "PBKDF2WITHHMACSHA512" in upper:
                return "PBKDF2-HMAC-SHA512", "password-hash", 0.97
            if "PBKDF2" in upper:
                return "PBKDF2", "password-hash", 0.9
            return "generic-kdf", "key-derivation", 0.75

        return "generic-crypto", "encryption", 0.6

    def _detect_java_jca_calls(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Java getInstance çağrılarını literal veya constant çözümleyerek tespit et."""
        constants = self._extract_java_string_constants(content)
        findings: List[Dict[str, Any]] = []
        call_pattern = re.compile(
            r'\b(Cipher|MessageDigest|Mac|Signature|KeyPairGenerator|KeyAgreement|SecretKeyFactory)\.getInstance\s*\(\s*([^\)]+?)\s*\)',
            re.IGNORECASE,
        )

        for m in call_pattern.finditer(content):
            api = m.group(1)
            raw_arg = m.group(2).strip()

            resolved_arg: Optional[str] = None
            literal = re.match(r'^"([^"]+)"$', raw_arg)
            if literal:
                resolved_arg = literal.group(1)
            else:
                token = raw_arg.split(".")[-1].strip()
                if raw_arg in constants:
                    resolved_arg = constants[raw_arg]
                elif token in constants:
                    resolved_arg = constants[token]

            algo, primitive_type, confidence = self._classify_java_getinstance(api, resolved_arg or "")
            line_num = content[:m.start()].count('\n') + 1
            snippet, context_before, context_after = self._extract_context_lines(lines, line_num)
            findings.append(
                {
                    "line": line_num,
                    "algorithm": algo,
                    "primitive_type": primitive_type,
                    "confidence": confidence,
                    "snippet": snippet,
                    "context_before": context_before,
                    "context_after": context_after,
                }
            )

        findings.extend(self._detect_java_crypto_operations(content, lines, constants))
        return findings

    def _detect_java_crypto_operations(
        self,
        content: str,
        lines: List[str],
        constants: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Java'da getInstance dışı kripto sinyallerini (constructors/ops) yakala."""
        findings: List[Dict[str, Any]] = []

        patterns = [
            # SecretKeySpec(..., "AES") -> algorithm hint from 2nd argument
            (
                re.compile(r"\bSecretKeySpec\s*\(\s*[^,]+,\s*([^\)]+)\)", re.IGNORECASE),
                "secret_key_spec",
            ),
            (re.compile(r"\bIvParameterSpec\s*\(", re.IGNORECASE), "iv_spec"),
            (re.compile(r"\bGCMParameterSpec\s*\(", re.IGNORECASE), "gcm_spec"),
            (re.compile(r"\bPBEKeySpec\s*\(", re.IGNORECASE), "pbe_key_spec"),
            (re.compile(r"\bSecureRandom\s*\.\s*getInstance\s*\(", re.IGNORECASE), "secure_random"),
            (re.compile(r"\bnew\s+SecureRandom\s*\(", re.IGNORECASE), "secure_random"),
            (re.compile(r"\bCipher\s*\.\s*doFinal\s*\(", re.IGNORECASE), "cipher_dofinal"),
            (re.compile(r"\bMessageDigest\s*\.\s*digest\s*\(", re.IGNORECASE), "digest"),
            (re.compile(r"\bMac\s*\.\s*doFinal\s*\(", re.IGNORECASE), "mac_dofinal"),
            (re.compile(r"\bSignature\s*\.\s*sign\s*\(", re.IGNORECASE), "signature_sign"),
            (re.compile(r"\bSignature\s*\.\s*verify\s*\(", re.IGNORECASE), "signature_verify"),
        ]

        for rx, kind in patterns:
            for m in rx.finditer(content):
                algo = "generic-crypto"
                primitive = "encryption"
                confidence = 0.7

                if kind == "secret_key_spec":
                    raw = (m.group(1) or "").strip()
                    lit = re.match(r'^"([^"]+)"$', raw)
                    resolved = None
                    if lit:
                        resolved = lit.group(1)
                    else:
                        token = raw.split(".")[-1].strip()
                        if raw in constants:
                            resolved = constants[raw]
                        elif token in constants:
                            resolved = constants[token]

                    upper = (resolved or "").upper()
                    if "AES" in upper:
                        algo, primitive, confidence = "AES", "block-cipher", 0.9
                    elif "RSA" in upper:
                        algo, primitive, confidence = "RSA", "asymmetric", 0.9
                    elif "CHACHA" in upper:
                        algo, primitive, confidence = "ChaCha20", "stream-cipher", 0.9
                    elif upper:
                        algo, primitive, confidence = upper, "block-cipher", 0.82
                    else:
                        algo, primitive, confidence = "generic-symmetric-key", "block-cipher", 0.7

                elif kind == "iv_spec":
                    algo, primitive, confidence = "generic-cipher", "encryption", 0.72
                elif kind == "gcm_spec":
                    algo, primitive, confidence = "AES-GCM", "authenticated-encryption", 0.88
                elif kind == "pbe_key_spec":
                    algo, primitive, confidence = "PBKDF2", "password-hash", 0.9
                elif kind == "secure_random":
                    algo, primitive, confidence = "CSPRNG", "random", 0.9
                elif kind == "cipher_dofinal":
                    algo, primitive, confidence = "generic-cipher", "encryption", 0.7
                elif kind == "digest":
                    algo, primitive, confidence = "generic-hash", "hash", 0.72
                elif kind == "mac_dofinal":
                    algo, primitive, confidence = "HMAC", "hmac", 0.74
                elif kind == "signature_sign":
                    algo, primitive, confidence = "generic-sign", "signing", 0.74
                elif kind == "signature_verify":
                    algo, primitive, confidence = "generic-verify", "verification", 0.74

                line_num = content[:m.start()].count('\n') + 1
                snippet, context_before, context_after = self._extract_context_lines(lines, line_num)
                findings.append(
                    {
                        "line": line_num,
                        "algorithm": algo,
                        "primitive_type": primitive,
                        "confidence": confidence,
                        "snippet": snippet,
                        "context_before": context_before,
                        "context_after": context_after,
                    }
                )

        return findings

    def _detect_java_import_signals(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Java import satırlarından context-only kripto sinyalleri üret."""
        findings: List[Dict[str, Any]] = []

        import_rules = [
            (r"\bimport\s+javax\.crypto\.Cipher\b", "generic-cipher", "encryption", 0.42),
            (r"\bimport\s+java\.security\.MessageDigest\b", "generic-hash", "hash", 0.42),
            (r"\bimport\s+javax\.crypto\.Mac\b", "HMAC", "hmac", 0.44),
            (r"\bimport\s+java\.security\.Signature\b", "generic-sign", "signing", 0.42),
            (r"\bimport\s+javax\.crypto\.SecretKeyFactory\b", "PBKDF2", "password-hash", 0.45),
            (r"\bimport\s+java\.security\.SecureRandom\b", "CSPRNG", "random", 0.45),
            (r"\bimport\s+javax\.crypto\.spec\.SecretKeySpec\b", "AES", "block-cipher", 0.4),
            (r"\bimport\s+javax\.crypto\.spec\.IvParameterSpec\b", "generic-cipher", "encryption", 0.4),
            (r"\bimport\s+javax\.crypto\.spec\.GCMParameterSpec\b", "AES-GCM", "authenticated-encryption", 0.44),
            (r"\bimport\s+javax\.crypto\.spec\.PBEKeySpec\b", "PBKDF2", "password-hash", 0.44),
            (r"\bimport\s+org\.springframework\.security\.crypto\.bcrypt\.BCryptPasswordEncoder\b", "bcrypt", "password-hash", 0.46),
            (r"\bimport\s+org\.springframework\.security\.crypto\.argon2\.Argon2PasswordEncoder\b", "argon2", "password-hash", 0.46),
            (r"\bimport\s+org\.springframework\.security\.crypto\.password\.Pbkdf2PasswordEncoder\b", "PBKDF2", "password-hash", 0.46),
        ]

        for pattern, algorithm, primitive_type, confidence in import_rules:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:m.start()].count('\n') + 1
                snippet, context_before, context_after = self._extract_context_lines(lines, line_num)
                findings.append(
                    {
                        "line": line_num,
                        "algorithm": algorithm,
                        "primitive_type": primitive_type,
                        "confidence": confidence,
                        "snippet": snippet,
                        "context_before": context_before,
                        "context_after": context_after,
                    }
                )

        return findings
    
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

    def _extract_context_lines(self, lines: List[str], line_num: int, window: int = 2) -> Tuple[str, str, str]:
        """Satır bazlı snippet ve çevre bağlamı çıkar."""
        if line_num < 1 or line_num > len(lines):
            return "", "", ""

        current = lines[line_num - 1].strip()
        before_start = max(0, line_num - 1 - window)
        before = "\n".join(lines[before_start: line_num - 1]).strip()
        after_end = min(len(lines), line_num + window)
        after = "\n".join(lines[line_num: after_end]).strip()
        return current, before, after

    def _extract_python_function_ranges(self, content: str, file_path: Path) -> List[Tuple[int, int, str]]:
        """Python dosyaları için fonksiyon kapsamlarını çıkar."""
        if file_path.suffix.lower() != ".py":
            return []
        try:
            tree = ast.parse(content)
        except Exception:
            return []

        ranges: List[Tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", start)
                if start is not None and end is not None:
                    ranges.append((start, end, node.name))
        return ranges

    def _resolve_function_name(self, line_num: int, ranges: List[Tuple[int, int, str]]) -> Optional[str]:
        """Satır numarasına karşılık gelen fonksiyon adını döndür."""
        for start, end, name in ranges:
            if start <= line_num <= end:
                return name
        return None
    
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

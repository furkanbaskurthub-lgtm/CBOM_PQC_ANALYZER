"""
Utility Fonksiyonları
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Dosyanın hash'ini hesapla
    
    Args:
        file_path: Dosya yolu
        algorithm: Hash algoritması (sha256, md5, etc.)
        
    Returns:
        Hash değeri
    """
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def validate_json(json_str: str) -> bool:
    """JSON geçerli mi kontrol et"""
    try:
        json.loads(json_str)
        return True
    except json.JSONDecodeError:
        return False


def format_size(bytes_size: int) -> str:
    """Dosya boyutunu insan okunur formata dönüştür"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"


def extract_json_from_text(text: str) -> Optional[Dict]:
    """Metinden JSON çıkart"""
    import re
    
    json_pattern = r'\{[\s\S]*\}'
    matches = re.finditer(json_pattern, text)
    
    for match in matches:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
    
    return None


def dedup_list(items: List) -> List:
    """Listeden çoğaltıları kaldır"""
    seen = set()
    result = []
    
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    
    return result


def merge_dictionaries(dict1: Dict, dict2: Dict, overwrite: bool = True) -> Dict:
    """İki sözlüğü birleştir"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value, overwrite)
        elif overwrite or key not in result:
            result[key] = value
    
    return result


def normalize_algorithm_name(algo_name: str) -> str:
    """Algoritma adını normalize et"""
    # Boşlukları sil, büyük harfe çevir
    normalized = algo_name.strip().upper()
    
    # Yaygın eşanlamlıları standartlaştır
    replacements = {
        "ADVANCED ENCRYPTION STANDARD": "AES",
        "RIVEST SHAMIR ADLEMAN": "RSA",
        "ELLIPTIC CURVE": "ECC",
        "SECURE HASH ALGORITHM": "SHA",
        "MESSAGE DIGEST": "MD",
    }
    
    for old, new in replacements.items():
        if old in normalized:
            normalized = normalized.replace(old, new)
    
    return normalized


class Logger:
    """Basit Logger"""
    
    def __init__(self, name: str):
        self.name = name
    
    def info(self, msg: str):
        print(f"[INFO] {self.name}: {msg}")
    
    def warning(self, msg: str):
        print(f"[WARN] {self.name}: {msg}")
    
    def error(self, msg: str):
        print(f"[ERROR] {self.name}: {msg}")
    
    def debug(self, msg: str):
        print(f"[DEBUG] {self.name}: {msg}")


if __name__ == "__main__":
    # Test
    test_str = '{"algorithm": "AES-256", "key_length": 256}'
    print(f"JSON Geçerlilik: {validate_json(test_str)}")
    print(f"Normalize: {normalize_algorithm_name('advanced encryption standard')}")
    print(f"Dedup: {dedup_list([1, 2, 2, 3, 1, 4])}")

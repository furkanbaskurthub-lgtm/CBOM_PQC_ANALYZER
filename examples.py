"""
PQC-Ready Analyzer - Örnek Kullanım Senaryoları
Bu betiği çalıştırarak analyzer'ı test edebilirsiniz
"""

import json
import tempfile
from pathlib import Path
from main import PQCReadyAnalyzer
from models.crypto_schema import calculate_risk_score


def example_1_cli_analysis():
    """Örnek 1: Komut Satırı Analizi"""
    print("\n" + "="*60)
    print("ÖRNEK 1: Stil Analiz CLI")
    print("="*60)
    
    # Test Python dosyası oluştur
    test_code = '''
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# RSA Key (Eski - Risk)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # ← Kyber'e geçiş önerilir
    backend=default_backend()
)

# SHA-256 Hash (Güvenli)
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"message")
hash_value = digest.finalize()

# MD5 (BROKEN - Acil Yüksel)
import hashlib
md5_hash = hashlib.md5(b"password")
'''
    
    # Temp dosya oluştur
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_path = f.name
    
    try:
        # Analiz
        analyzer = PQCReadyAnalyzer()
        cbom = analyzer.analyze_target(temp_path, use_llm=False)
        
        print(f"\n✅ Analiz tamamlandı!")
        print(f"📊 Genel Risk Skoru: {cbom.risk_score:.1f}/100")
        print(f"🔐 Tespit Edilen Bileşen: {len(cbom.crypto_assets)}")
        
        # Detay
        for asset in cbom.crypto_assets:
            risk = calculate_risk_score(asset.algorithm.name)
            print(f"\n  {asset.algorithm.name}")
            print(f"    Risk: {risk.final_risk:.1f}/100 ({asset.risk_level})")
            print(f"    PQC: {'✅' if asset.algorithm.is_pqc_safe else '❌'}")
            print(f"    Tavsiye: {risk.recommendation[:60]}...")
        
        # CBOM kaydet
        output_file = analyzer.save_cbom_json(cbom)
        print(f"\n💾 CBOM kaydedildi: {output_file}")
    
    finally:
        Path(temp_path).unlink()


def example_2_risk_scoring():
    """Örnek 2: Risk Puanlama"""
    print("\n" + "="*60)
    print("ÖRNEK 2: NIST PQC Risk Puanlama")
    print("="*60)
    
    algorithms = [
        ("RSA", 2048),
        ("RSA", 4096),
        ("AES", 256),
        ("SHA-1", None),
        ("SHA-256", None),
        ("MD5", None),
        ("Kyber", 1024),
        ("Dilithium", None),
    ]
    
    print(f"\n{'Algoritma':<20} {'Anahtar':<10} {'Risk':<8} {'PQC':<5} {'Tavsiye':<40}")
    print("-" * 90)
    
    for algo, key_len in algorithms:
        risk = calculate_risk_score(algo, key_len)
        pqc = "✅" if risk.pqc_compliance > 50 else "❌"
        risk_level = "🔴 Critical" if risk.final_risk > 80 else (
            "🟠 High" if risk.final_risk > 60 else (
            "🟡 Medium" if risk.final_risk > 40 else "🟢 Low"
        ))
        
        print(f"{algo:<20} {str(key_len) if key_len else 'N/A':<10} "
              f"{risk.final_risk:<8.1f} {pqc:<5} {risk_level}")


def example_3_pqc_migration():
    """Örnek 3: PQC Yükseltme Planı"""
    print("\n" + "="*60)
    print("ÖRNEK 3: PQC Yükseltme Tavsiyesi")
    print("="*60)
    
    migration_paths = {
        "RSA": {
            "recommendation": "Kyber/ML-KEM",
            "timeline": "3-6 ay",
            "risk_before": 85,
            "risk_after": 10
        },
        "ECDSA": {
            "recommendation": "Dilithium/ML-DSA",
            "timeline": "3-6 ay",
            "risk_before": 75,
            "risk_after": 10
        },
        "SHA-1": {
            "recommendation": "SHA-256 / SHA-512",
            "timeline": "1-3 ay",
            "risk_before": 80,
            "risk_after": 25
        },
        "MD5": {
            "recommendation": "SHA-256 Acil!",
            "timeline": "< 1 ay",
            "risk_before": 95,
            "risk_after": 25
        },
        "AES": {
            "recommendation": "Koruma yok, güvenli",
            "timeline": "N/A",
            "risk_before": 25,
            "risk_after": 25
        }
    }
    
    print(f"\n{'Algoritma':<15} {'Ev':<25} {'Takvim':<15} {'Risk İyile':<20}")
    print("-" * 75)
    
    for algo, info in migration_paths.items():
        improvement = f"{info['risk_before']} → {info['risk_after']}"
        print(f"{algo:<15} {info['recommendation']:<25} {info['timeline']:<15} {improvement:<20}")


def example_4_report_generation():
    """Örnek 4: Rapor Oluşturma"""
    print("\n" + "="*60)
    print("ÖRNEK 4: Kapsamlı Rapor Oluşturma")
    print("="*60)
    
    # Test dosyası
    test_code = '''
import hashlib
from Crypto.Cipher import AES, RSA

# Legacy Hash
md5 = hashlib.md5()
md5.update(b"password")

# RSA Encryption
key = RSA.generate(2048)
cipher = AES.new(key, AES.MODE_CBC)
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_path = f.name
    
    try:
        analyzer = PQCReadyAnalyzer()
        cbom = analyzer.analyze_target(temp_path, use_llm=False)
        report = analyzer.generate_report(cbom)
        
        print(f"\n📋 RAPOR ÖZETİ")
        print(f"  Tarama Tarihi: {report['statistics']['scan_date']}")
        print(f"  Dosya: {report['statistics']['target_file']}")
        print(f"  Toplam Bileşen: {report['statistics']['total_crypto_components']}")
        print(f"  PQC Hazır: {report['statistics']['pqc_ready']}")
        print(f"  Genel Risk: {report['recommendations']['overall_score']:.1f}/100")
        
        print(f"\n⚠️ KRİTİK SORUNLAR:")
        for issue in report['recommendations']['critical_issues']:
            print(f"  🔴 {issue['algorithm']}: {issue['recommendation']}")
        
        print(f"\n⚡ YÜKSEK ÖNCELİK:")
        for issue in report['recommendations']['high_priority']:
            print(f"  🟠 {issue['algorithm']}: Risk {issue['current_risk']:.1f}")
        
        # Rapor kaydet
        report_path = analyzer.output_dir / f"report_{cbom.bom_ref}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Rapor kaydedildi: {report_path}")
    
    finally:
        Path(temp_path).unlink()


def example_5_batch_analysis():
    """Örnek 5: Toplu Analiz"""
    print("\n" + "="*60)
    print("ÖRNEK 5: Toplu Dosya Analizi")
    print("="*60)
    
    # Test dosyaları oluştur
    test_files = {
        "crypto_secure.py": '''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
''',
        "crypto_legacy.py": '''
import hashlib
import rsa

# SHA-1 (Legacy)
sha1 = hashlib.sha1()
sha1.update(b"data")

# RSA (Eski)
key = rsa.newkeys(2048)
''',
        "crypto_modern.py": '''
from libnacl.crypto_hash import sha256
from libnacl.crypto_box import Box

# libsodium (Modern PQC-Ready)
hash_result = sha256(b"data")
box = Box()
'''
    }
    
    analyzer = PQCReadyAnalyzer()
    results = {}
    
    print(f"\n{'Dosya':<25} {'Bileşen':<10} {'Risk':<10} {'Status':<15}")
    print("-" * 60)
    
    for filename, code in test_files.items():
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            cbom = analyzer.analyze_target(temp_path, use_llm=False)
            results[filename] = {
                "risk_score": cbom.risk_score,
                "components": len(cbom.crypto_assets)
            }
            
            status = "🟢 Güvenli" if cbom.risk_score < 40 else (
                "🟡 Orta" if cbom.risk_score < 60 else "🔴 Risk"
            )
            
            print(f"{filename:<25} {len(cbom.crypto_assets):<10} "
                  f"{cbom.risk_score:<10.1f} {status:<15}")
        
        finally:
            Path(temp_path).unlink()
    
    # Özet
    print("\n📊 TOPLU ÖZET:")
    avg_risk = sum(r['risk_score'] for r in results.values()) / len(results)
    print(f"  Ortalama Risk: {avg_risk:.1f}/100")
    print(f"  Dosya Sayısı: {len(results)}")
    print(f"  Toplam Bileşen: {sum(r['components'] for r in results.values())}")


def main():
    """Ana Hiç Çalıştırıcı"""
    print("""
    
    ╔════════════════════════════════════════════════════════╗
    ║  🔐 PQC-Ready Analyzer - Örnek Senaryolar             ║
    ║                                                        ║
    ║  Post-Quantum Cryptography Hazırlık Analiz Aracı      ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    examples = {
        "1": ("Temel CLI Analizi", example_1_cli_analysis),
        "2": ("Risk Puanlama", example_2_risk_scoring),
        "3": ("PQC Yükseltme Tavsiyesi", example_3_pqc_migration),
        "4": ("Rapor Oluşturma", example_4_report_generation),
        "5": ("Toplu Analiz", example_5_batch_analysis),
        "6": ("Tümü Çalıştır", None),
    }
    
    print("\nÖRNEK SEÇİMİ:\n")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    
    # Tümü çalıştır
    print("\n🚀 Tüm örnekler çalıştırılıyor...\n")
    
    for key, (name, func) in examples.items():
        if key != "6" and func:
            try:
                func()
            except Exception as e:
                print(f"\n❌ {name} hatası: {str(e)}")
    
    print("\n" + "="*60)
    print("✅ Örnek Senaryoları Tamamlandı!")
    print("="*60)
    print("\n📁 Çıktılar output/ klasöründe kaydedildi")
    print("\n📖 Daha fazla bilgi için README.md'ye bakın")


if __name__ == "__main__":
    main()

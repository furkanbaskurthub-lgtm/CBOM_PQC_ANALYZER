# ⚡ PQC-Ready Analyzer - Hızlı Başlangıç

30 saniyede başlayın!

---

## 1️⃣ Kurulum

```bash
# Python 3.9+ gerekli
python --version

# Repo'yu klonla
git clone https://github.com/yourusername/pqc-ready-analyzer.git
cd pqc-ready-analyzer

# Virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate     # Windows

# Paketleri yükle
pip install -r requirements.txt
```

---

## 2️⃣ İlk Analiz

### Seçenek A: Komut Satırı (En Hızlı)

```bash
# Herhangi bir binary veya source dosyası analiz et
python main.py /usr/bin/openssl

# Çıktı: output/cbom_abc123.json
```

**Sonuç Örneği:**

```json
{
  "bom_ref": "cbom-xyz",
  "target_file": "/usr/bin/openssl",
  "risk_score": 62.5,
  "crypto_assets": [
    {
      "algorithm": { "name": "RSA", "is_pqc_safe": false },
      "risk_level": "high"
    }
  ]
}
```

### Seçenek B: Web Arayüzü (Daha Gözel)

```bash
# Streamlit sunucusu başlat
streamlit run app.py

# Tarayıcıda aç: http://localhost:8501
```

**Adımlar:**

1. 📁 Sol panelden dosya yükle
2. 🔍 "Analiz Başlat" butonuna bas
3. 📊 Grafikleri ve önerileri gözlemle
4. 📥 CBOM/Rapor indir

---

## 3️⃣ Örnek Analizler

### Python Dosyasını Analiz Et

```bash
# test.py oluştur
cat > test.py << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# RSA Key oluştur
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048  # ← Eski! Kyber'e geçiş önerilir
)

# SHA-256 Hash (güvenli)
data = b"Hello World"
digest = hashes.Hash(hashes.SHA256())
digest.update(data)
EOF

# Analiz Et
python main.py test.py
```

**Rapor:**

- ✅ SHA-256: Risk 25/100 (Güvenli)
- ❌ RSA-2048: Risk 85/100 (Acil yüksel)

### ELF Binary Analizi

```bash
# Örnek: OpenSSL binary (Linux)
python main.py /usr/bin/openssl

# Bulunacak Kütüphaneler:
# - libcrypto.so.1.1 → OpenSSL
# - Semboller: RSA_sign, AES_encrypt, SHA256_Init vb.
```

---

## 4️⃣ LLM Analizini Etkinleştir (İsteğe Bağlı)

### OpenAI Kullanarak

```bash
# API anahtarını al: https://platform.openai.com/api-keys

# .env dosyası oluştur
cat > .env << 'EOF'
OPENAI_API_KEY=sk-your-key-here
LLM_PROVIDER=openai
USE_LLM=true
EOF

# Kaynak kodu LLM ile analiz et
python -c "
from main import PQCReadyAnalyzer
analyzer = PQCReadyAnalyzer()
cbom = analyzer.analyze_target('test.py', use_llm=True)
analyzer.save_cbom_json(cbom)
"
```

### Ollama Kullanarak (Ücretsiz, Offline)

```bash
# Ollama'yı indir: https://ollama.ai/

# Modeli başlat
ollama run mistral

# config.py güncelle veya .env ayarla
export OLLAMA_MODEL=mistral
export LLM_PROVIDER=ollama

# Analiz başlat
python main.py test.py
```

---

## 5️⃣ Sonuçları Anlama

### Risk Seviyeleri

| Level           | Skor   | Anlamı                     | Aksiyonu            |
| --------------- | ------ | -------------------------- | ------------------- |
| 🔴 **Critical** | 80-100 | Ani kriptanaliz riski      | **Hemen Düzelt**    |
| 🟠 **High**     | 60-79  | Uzun vadede uygun değil    | **Bu Yıl Planla**   |
| 🟡 **Medium**   | 40-59  | Gelişime açık, ama güvenli | **Sonraki Sürümde** |
| 🟢 **Low**      | 0-39   | PQC ready veya modern      | **Koruma Yok**      |

### Örnek Öneriler

```
🔴 RSA-2048
  Risk: 85/100
  Tavsiye: ACIL - Bu algoritmanın kullanımını durdur
  Çözüm: Kyber/ML-KEM anahtar anlaşması kullan
  Takvim: ≤ 3 ay

✅ AES-256-GCM
  Risk: 15/100
  Tavsiye: İYİ - Algorit güvenli ancak PQC dönüşümünü planla
  Durum: Koruma yok, ancak uzun vadede sorun değil
  Takvim: 2-3 sene

⚠️ SHA-1
  Risk: 80/100
  Tavsiye: UYAR - Kısa vadede phasing-out planını yap
  Çözüm: SHA-256+ kullan
  Takvim: ≤ 6 ay
```

---

## 6️⃣ Ortak Görevler

### Bütün Projeyi Taramak

```bash
# Klasördeki tüm dosyaları analiz et
for file in $(find . -type f -name "*.py" -o -name "*.c"); do
  python main.py "$file"
done

# Tüm sonuçları birleştir
cat output/cbom_*.json > combined_cbom.json
```

### Docker Yükle

```bash
# Dockerfile (sağlanıyor)
docker build -t pqc-analyzer .
docker run -p 8501:8501 pqc-analyzer
# http://localhost:8501'de erişebilirsin
```

### GitHub Actions'ta Otomatik Tarama

```yaml
# .github/workflows/pqc-scan.yml
name: PQC Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run PQC scan
        run: |
          python main.py src/
          ls -la output/
      - name: Upload CBOM
        uses: actions/upload-artifact@v3
        with:
          name: cbom-results
          path: output/cbom_*.json
```

---

## 7️⃣ Sorun Giderme

### "pyelftools yüklü değil" Hatası

```bash
pip install pyelftools pefile
```

### "OpenAI API Key Geçersiz" Hatası

```bash
# API anahtarını kontrol et
echo $OPENAI_API_KEY

# Yanlışsa güncelle
export OPENAI_API_KEY="sk-..."
```

### "Ollama bağlanılamıyor" Hatası

```bash
# Ollama çalışıyor mu kontrol et
curl http://localhost:11434/api/tags

# Çalışmıyorsa başlat
ollama serve
```

### Analiz Çok Yavaş

```bash
# LLM'i devre dışı bırak
export USE_LLM=false

# veya batch processing kullan
# (yakında eklenecek)
```

---

## 📚 Sonraki Adımlar

1. ✅ **Basit Analiz**: `python main.py test.py`
2. ✅ **Web UI**: `streamlit run app.py`
3. ✅ **LLM Etkinleştir**: `.env` ayarları
4. ✅ **Entegrasyon**: CI/CD pipeline'a ekle
5. ✅ **Raporlama**: Otomatik CBOM üretimi

---

## 🎯 Örnek Amaçları

- [ ] Kritik RSA algoritmasını Kyber'e taşı
- [ ] SHA-1 kullanımını kaldır
- [ ] TLS 1.3 + PQC desteği ekle
- [ ] Sertifikaları SHA-256 ile yenile
- [ ] Libc güncelle (moderne ne)

---

## 📞 Yardım

Sıkıntı mı?

- 📖 [README.md](README.md)'yi oku
- 🐛 [Issues](../../issues)'de soru sor
- 💬 [Discussions](../../discussions)'a katıl

Happy analyzing! 🚀

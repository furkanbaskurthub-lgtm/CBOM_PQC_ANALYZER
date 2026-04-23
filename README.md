# PQC-Ready Analyzer

Bu projeyi mülakatta anlatmak için, aşağıdaki akışla ve birinci şahıs anlatımıyla tasarladım.

## Proje Özeti

Bu projede amacım, bir dosyanın (kaynak kod veya binary) içinde kullanılan kriptografik bileşenleri tespit edip CycloneDX v1.5 formatında CBOM (Cryptography Bill of Materials) üretmekti. Sonrasında bu bulguları NIST PQC bakış açısıyla risk puanına dönüştürüp görsel bir dashboard üzerinde sunmayı hedefledim.

## Ben Bu Projede Ne Yaptım

1. [models/crypto_schema.py](models/crypto_schema.py) dosyasında CycloneDX uyumlu veri modellerini oluşturdum.
2. [analyzer/static_engine.py](analyzer/static_engine.py) dosyasında ELF/PE ve source-code tarafı için statik analiz motorunu yazdım.
3. [analyzer/llm_engine.py](analyzer/llm_engine.py) dosyasında OpenAI/HuggingFace/Ollama destekli LLM analiz katmanını ekledim.
4. [main.py](main.py) dosyasında tüm akışı orkestre eden ana servis sınıfını geliştirdim.
5. [app.py](app.py) dosyasında Streamlit tabanlı dashboard kurdum; kullanıcı dosya yükleyip risk ve CBOM çıktısını görebiliyor.
6. [config.py](config.py), [.env.example](.env.example) ve [.env](.env) üzerinden konfigürasyonu çevresel değişkenlerle yönetilebilir hale getirdim.

## Dosya Bazlı Teknik Katkım

### 1) Veri Modeli

- Dosya: [models/crypto_schema.py](models/crypto_schema.py)
- Yaptığım işler:
  - `CryptoBOM`, `CryptoAsset`, `AlgorithmDetails` modellerini oluşturdum.
  - `PrimitiveType` ve `CryptoFunction` enumları ile standartlaştırma yaptım.
  - NIST PQC risk eşleme tablosunu (`NIST_PQC_RISK_MAP`) ve `calculate_risk_score` fonksiyonunu yazdım.

### 2) Statik Analiz Motoru

- Dosya: [analyzer/static_engine.py](analyzer/static_engine.py)
- Yaptığım işler:
  - ELF analizinde sembol ve bağlı kütüphane taraması ekledim.
  - PE analizinde import tablosuna ek olarak export sembol taramasını da devreye aldım.
  - OpenSSL, wolfSSL, libcrypto ve Windows BCrypt fonksiyon eşleştirmelerini tanımladım.
  - Kaynak kod için regex tabanlı fonksiyon tespit mekanizması kurdum.
  - `bcrypt.dll` gibi dosyaların 0.0 dönmesi sorununu, `BCrypt*`/`NCrypt*` eşleştirmeleri ile çözdüm.

### 3) LLM Analiz Katmanı

- Dosya: [analyzer/llm_engine.py](analyzer/llm_engine.py)
- Yaptığım işler:
  - LLM çıktısını JSON formatında parse edip güvenli şekilde modele dönüştürdüm.
  - Geçersiz JSON döndüğünde kırılmayan fallback/error handling ekledim.
  - Provider bazlı yapı kurdum: `openai`, `huggingface`, `ollama`, `mock`.

### 4) Ana Orkestrasyon

- Dosya: [main.py](main.py)
- Yaptığım işler:
  - `PQCReadyAnalyzer` sınıfı ile uçtan uca analiz akışı tasarladım.
  - Statik analiz sonucu -> varlık modeli -> risk hesabı -> CBOM JSON sürecini bağladım.
  - LLM’i sadece source-code için zenginleştirme katmanı olarak konumlandırdım.
  - `.env` ile provider seçimini okuyup API key yoksa otomatik `mock` moda düşen güvenli davranış ekledim.

### 5) Dashboard

- Dosya: [app.py](app.py)
- Yaptığım işler:
  - Dosya yükleme, analiz tetikleme, tablo/grafik/tavsiye sekmelerini geliştirdim.
  - Plotly ile dağılım grafiklerini ekledim.
  - Streamlit session-state kaynaklı stale analyzer sorununu giderdim.
  - Pandas 3 uyumluluğu için tablo stillerinde `Styler.map` kullanımını düzelttim.

## Mimarim (Kısa)

- Girdi: kullanıcı dosya yükler
- Analiz 1: statik motor dosyayı tarar
- Analiz 2 (opsiyonel): LLM source-code bağlamını zenginleştirir
- Değerlendirme: NIST PQC risk hesabı yapılır
- Çıktı: CBOM JSON + dashboard tabloları/grafikleri

## LLM’li ve LLM’siz Çalıştırma Farkı

- LLM’siz:
  - Daha hızlı, daha deterministik, maliyetsiz
  - Özellikle binary taramada ana yöntem
- LLM’li:
  - Source-code tarafında bağlamsal yorum gücü yüksek
  - API maliyeti ve latency ekler

## Kurulum

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Çalıştırma

### 1) Dashboard

```bash
streamlit run app.py
```

### 2) CLI

```bash
python main.py C:\Windows\System32\bcrypt.dll
python main.py C:\path\to\openssl.exe
python main.py samples\sample_crypto.py
```

## .env Hazırlığı

- Dosya: [.env](.env)
- Minimum OpenAI kullanım örneği:

```env
LLM_PROVIDER=openai
USE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```

- API key girilmezse sistem güvenli şekilde `mock` moda düşer.

## Mülakatta Canlı Demo Akışı

1. Dashboard’ı açarım ve [samples/sample_crypto.py](samples/sample_crypto.py) yüklerim.
2. Sonra binary örneği olarak `openssl.exe` veya `bcrypt.dll` ile gerçek tarama gösteririm.
3. `Algoritma Detayları` sekmesinde yakalanan varlıkları ve risk seviyesini anlatırım.
4. `İndir` sekmesinden CBOM çıktısını alıp otomasyon entegrasyonu senaryosunu açıklarım.

## Karşılaştığım Problemler ve Çözümlerim

- Problem: Bazı DLL dosyalarında sonuç 0.0 görünüyordu.
  - Çözüm: PE export taraması + `BCrypt*`/`NCrypt*` mapping ekledim.
- Problem: UI’da eski analyzer state’i kalıyordu.
  - Çözüm: Her analizde taze analyzer oluşturup session state’i güncelledim.
- Problem: Pandas 3 ile stil API değişimi hatası.
  - Çözüm: `applymap` yerine uyumlu `map` kullanımına geçtim.

## Kısa Sonuç

Bu proje ile statik analiz, risk puanlama, CBOM üretimi ve dashboard sunumunu tek bir akışta birleştirdim. Mülakatta hem teknik derinliği hem de ürünleşmiş çıktıyı birlikte gösterebilecek bir PoC ortaya koydum.

# PQC-Ready Analyzer

Python tabanlı bu proje, kaynak kodları ve binary dosyaları tarayarak kriptografik kullanım izlerini tespit eden, bunları CycloneDX v1.5 uyumlu CBOM formatına dönüştüren ve NIST PQC perspektifiyle risk puanı üreten bir analiz aracıdır.

## Neyi Hedefliyor?

Bu aracı, bir yazılım sisteminin hangi kriptografik algoritmaları kullandığını hızlıca görmek, legacy algoritmaları ayıklamak ve post-quantum geçiş sürecini planlamak için geliştirdim. Amaç yalnızca tespit yapmak değil; aynı zamanda tespit edilen bileşenleri anlaşılır bir risk çerçevesine oturtmak.

## Ana Özellikler

- Kaynak kod ve binary analiz desteği
- ELF ve PE dosyalarında sembol/import/export taraması
- OpenSSL, wolfSSL, libcrypto ve Windows BCrypt/NCrypt eşleştirmeleri
- LLM destekli bağlamsal analiz (OpenAI, HuggingFace, Ollama, mock)
- CycloneDX v1.5 uyumlu CBOM üretimi
- NIST PQC risk skoru ve tavsiye motoru
- Streamlit tabanlı web arayüzü
- JSON ve CSV çıktı alma

## Projede Neler Yaptım?

- [models/crypto_schema.py](models/crypto_schema.py) içinde CBOM veri modelini kurdum.
- [analyzer/static_engine.py](analyzer/static_engine.py) ile statik analiz motorunu yazdım.
- [analyzer/llm_engine.py](analyzer/llm_engine.py) ile LLM entegrasyon katmanını ekledim.
- [main.py](main.py) ile tüm analiz akışını orkestre ettim.
- [app.py](app.py) ile kullanıcı dostu Streamlit arayüzü oluşturdum.
- [.env](.env), [.env.example](.env.example) ve [config.py](config.py) ile konfigürasyonu yönetilebilir hale getirdim.

## Mimari

1. Kullanıcı bir dosya yükler.
2. [analyzer/static_engine.py](analyzer/static_engine.py) dosyayı tarar ve kripto izlerini çıkarır.
3. [analyzer/llm_engine.py](analyzer/llm_engine.py) aktifse bağlamsal yorum ekler.
4. [main.py](main.py) varlıkları CBOM modeline dönüştürür.
5. Risk skoru hesaplanır ve sonuç [app.py](app.py) üzerinde gösterilir.

## Dosya Yapısı

```text
PQC_READY_ANALYZER/
├── analyzer/
├── models/
├── utils/
├── samples/
├── output/
├── app.py
├── main.py
├── config.py
├── requirements.txt
└── README.md
```

## Kurulum

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Çalıştırma

### Streamlit Arayüzü

```powershell
streamlit run app.py
```

### Komut Satırı

```powershell
python main.py samples\sample_crypto.py
python main.py C:\Windows\System32\bcrypt.dll
python main.py C:\Windows\System32\openssl.exe

# Repository batch etiketleme (profile tabanlı)
python run_repo_batch.py C:\path\to\apache-fineract --profile fineract-java

# Paralel worker ile daha hizli tarama
python run_repo_batch.py C:\path\to\apache-fineract --profile fineract-java --workers 8

# GitHub URL ile tarama (otomatik clone + cleanup)
python run_repo_batch.py --repo-url https://github.com/apache/fineract --profile fineract-java --workers 8

# Hızlı ama doğru LLM modu (aday dosya + az snippet)
python run_repo_batch.py --repo-url https://github.com/apache/fineract --profile fineract-java --use-llm --llm-candidate-only --llm-min-confidence 0.85 --llm-max-snippets 2 --workers 4

# QuickFIX C++ profili ile statik odaklı tarama
python run_repo_batch.py --repo-url https://github.com/quickfix/quickfix --profile quickfix-cpp --use-llm False --workers 6

# QuickFIX için LLM destekli tarama (candidate-only kapalı)
python run_repo_batch.py --repo-url https://github.com/quickfix/quickfix --profile quickfix-cpp --use-llm --llm-candidate-only False --llm-min-confidence 0.6 --llm-max-snippets 2 --workers 6
```

## Repository Profilleri

- `fineract-java`: Java/JCA odaklı tarama profili
- `default-source`: genel kaynak kod tarama profili
- `quickfix-cpp`: QuickFIX ve benzeri C++ repo'larında `UtilitySSL`, `SSLSocket*` ve OpenSSL/TLS kullanımını yakalamak için hedefli profil

QuickFIX üzerinde bu profil ile statik-only çalışmada `assets_total=10` ve `training=10` sonuçlarını aldım; önceki `0 asset` problemi bu hedefli profil ve statik TLS/OpenSSL kuralları ile çözüldü.

## LLM Kullanımı

Bu proje LLM’i opsiyonel bir zenginleştirme katmanı olarak kullanır.

### Ollama

`.env` içine şunu yazdım:

```env
LLM_PROVIDER=ollama
USE_LLM=true
OLLAMA_MODEL=llama3.1
```

### OpenAI

```env
LLM_PROVIDER=openai
USE_LLM=true
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```

API key yoksa sistem güvenli şekilde `mock` moda düşer.

## Ben Bu Projede Nasıl Konumlandırıyorum?

Bu projeyi mülakatta şöyle anlatıyorum:

"Ben önce statik analiz motorunu yazdım ve binary/source içindeki kriptografik izleri tespit ettim. Sonra bu bulguları CycloneDX uyumlu CBOM modeline dönüştürdüm. Ardından NIST PQC risk tablosu ile legacy algoritmaları puanladım ve sonuçları Streamlit dashboard üzerinde görselleştirdim. LLM katmanını da bağlamsal yorum ve zenginleştirme için ekledim."

## Demo Senaryosu

1. [samples/sample_crypto.py](samples/sample_crypto.py) ile temel tespiti gösteriyorum.
2. [samples/complex_crypto_lab.py](samples/complex_crypto_lab.py) ile LLM farkını anlatıyorum.
3. `C:\Windows\System32\bcrypt.dll` veya `openssl.exe` ile binary analiz gösteriyorum.
4. İndirilen CBOM JSON üzerinden risk ve algoritma listesini yorumluyorum.

## Çıktı Örnekleri

- CBOM JSON
- Risk özeti
- Algoritma dağılımı grafikleri
- Migrasyon tavsiyeleri

QuickFIX örneği için run klasöründe şu dosyalar üretilir:

- `quickfix_cbom_cyclonedx.json`
- `quickfix_cbom_confirmed.json`
- `quickfix_cbom_context.json`
- `quickfix_labeled_v2.json`
- `quickfix_dataset_training.jsonl`
- `quickfix_dataset_review.jsonl`
- `quickfix_dataset_policy_drop.jsonl`
- `quickfix_dataset_quality_reject.jsonl`
- `quickfix_dataset_dropped.jsonl`
- `quickfix_batch_summary.json`

## Karşılaştığım Sorunlar

- `bcrypt.dll` ilk başta 0.0 sonuç veriyordu. PE export taraması ve BCrypt mapping ile çözdüm.
- Streamlit session-state eski analyzer nesnesini tutuyordu. Her analizde taze analyzer oluşturarak düzelttim.
- Pandas 3 ile `Styler.applymap` uyumsuzdu. `Styler.map` ile güncelledim.
- Ollama çıktısı parse sorunları yaratabiliyordu. JSON zorlaması ve daha sıkı parse akışı ekledim.
- QuickFIX gibi C++ repo'larında `default-source` profili yeterli değildi. `quickfix-cpp` profili ve OpenSSL/TLS statik kuralları ile kapsama alanını genişlettim.

## Neden Bu Proje Önemli?

Bu araç, yazılım güvenliği ve kriptografik envanter çıkarımı açısından pratik bir PoC sağlıyor. Özellikle PQC dönüşümü planlanan sistemlerde hangi algoritmaların riskli olduğunu hızlıca gösterebiliyor.

## Gelecek Geliştirmeler

- Recursive klasör tarama
- CBOM diff raporu
- PDF/Markdown export
- CI/CD entegrasyonu
- Daha gelişmiş binary string scanning
- Daha ayrıntılı migration suggestion engine

## Lisans

Bu proje kişisel kullanım ve demo amaçlı geliştirilmiştir. İstersen burada bir lisans dosyası da ekleyebilirim.

## İletişim

Repo: [CBOM_PQC_ANALYZER](https://github.com/furkanbaskurthub-lgtm/CBOM_PQC_ANALYZER)

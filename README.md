# PQC-Ready Analyzer

Python tabanlı bu proje, kaynak kodları ve binary dosyaları tarayarak kriptografik kullanım izlerini tespit eden, bunları CycloneDX v1.5 uyumlu CBOM formatına dönüştüren ve NIST PQC perspektifiyle risk skoru üreten bir analiz aracıdır.

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

- `models/crypto_schema.py` içinde CBOM veri modelini kurdum.
- `analyzer/static_engine.py` ile statik analiz motorunu yazdım.
- `analyzer/llm_engine.py` ile LLM entegrasyon katmanını ekledim.
- `main.py` ile tüm analiz akışını orkestre ettim.
- `app.py` ile kullanıcı dostu Streamlit arayüzü oluşturdum.
- `.env`, `.env.example` ve `config.py` ile konfigürasyonu yönetilebilir hale getirdim.

## Mimari

1. Kullanıcı bir dosya yükler.
2. `analyzer/static_engine.py` dosyayı tarar ve kripto izlerini çıkarır.
3. `analyzer/llm_engine.py` aktifse LLM İLE bağlamsal yorum ekler.
4. `main.py` varlıkları CBOM modeline dönüştürür.
5. Risk skoru hesaplanır ve sonuç `app.py` üzerinde gösterilir.

## KURULUM
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

##ÇALIŞTIRMA
streamlit run app.py


LLM Kullanımı
Bu proje LLM’i opsiyonel bir zenginleştirme katmanı olarak kullanır.

Ollama
.env içine şunu yazdım:
LLM_PROVIDER=ollama
USE_LLM=true
OLLAMA_MODEL=llama3.1
(BUNU YAPMAK İÇİN OLLAMA 3.1 SÜRÜMÜNÜ KURMANIZ GEREKİYOR EĞER Kİ OPENAI GİBİ BİR API KULLANACAKSINIZ ENV MİMARİSİNİ ONA GÖRE DİZAYN EDİNİZ.)


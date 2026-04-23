"""
Hızlı ve basit hisse senedi tahmin aracı
Kullanıcı şirket seçer, yıl girer ve anında sonuç alır
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import yfinance as yf
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score
from src.config import RANDOM_STATE


# Popüler hisse senetleri listesi
HISSE_LISTESI = {
    "1": ("Akbank", "AKBNK.IS"),
    "2": ("Garanti BBVA", "GARAN.IS"),
    "3": ("İş Bankası", "ISCTR.IS"),
    "4": ("Yapı Kredi", "YKBNK.IS"),
    "5": ("Türk Hava Yolları", "THYAO.IS"),
    "6": ("ASELSAN", "ASELS.IS"),
    "7": ("Koç Holding", "KCHOL.IS"),
    "8": ("Ereğli Demir Çelik", "EREGL.IS"),
    "9": ("Turkcell", "TCELL.IS"),
    "10": ("BIM", "BIMAS.IS"),
    "11": ("Apple", "AAPL"),
    "12": ("Microsoft", "MSFT"),
    "13": ("Tesla", "TSLA"),
    "14": ("Amazon", "AMZN"),
    "15": ("Google", "GOOGL"),
}


def goster_hisse_listesi():
    """Hisse senedi listesini göster"""
    print("\n" + "="*70)
    print("📊 HİSSE SENEDİ LİSTESİ")
    print("="*70)
    
    # BIST hisseleri
    print("\n🇹🇷 BORSA İSTANBUL:")
    for key, (name, ticker) in list(HISSE_LISTESI.items())[:10]:
        print(f"   {key:>2}. {name:<25} ({ticker})")
    
    # Uluslararası hisseler
    print("\n🌍 ULUSLARARASI:")
    for key, (name, ticker) in list(HISSE_LISTESI.items())[10:]:
        print(f"   {key:>2}. {name:<25} ({ticker})")
    
    print("\n   0. Manuel hisse kodu gir")
    print("="*70)


def hisse_sec():
    """Kullanıcıdan hisse seçimi al"""
    while True:
        goster_hisse_listesi()
        secim = input("\n👉 Hisse seçin (numara): ").strip()
        
        if secim == "0":
            ticker = input("Hisse kodunu girin (örn: THYAO.IS): ").strip().upper()
            name = ticker
            return name, ticker
        
        if secim in HISSE_LISTESI:
            name, ticker = HISSE_LISTESI[secim]
            return name, ticker
        
        print("❌ Geçersiz seçim! Lütfen listeden bir numara seçin.")


def yil_al():
    """Kullanıcıdan yıl bilgisi al"""
    while True:
        try:
            yil = input("\n📅 Kaç yıl sonrası için tahmin? (1-10): ").strip()
            yil = int(yil)
            
            if 1 <= yil <= 10:
                return yil
            else:
                print("❌ Lütfen 1 ile 10 arasında bir sayı girin!")
        except ValueError:
            print("❌ Lütfen geçerli bir sayı girin!")


def veri_cek_ve_tahmin_yap(ticker: str, name: str, yil: int):
    """Veri çek, model eğit ve tahmin yap"""
    try:
        print(f"\n⏳ {name} için veri çekiliyor...")
        
        # Veri çek
        stock_data = yf.Ticker(ticker)
        data = stock_data.history(period="5y")
        
        if data.empty:
            print(f"❌ {name} için veri bulunamadı!")
            return None
        
        print(f"✅ {len(data)} günlük veri çekildi")
        
        # Özellik mühendisliği
        print("⏳ Özellikler hazırlanıyor...")
        data["Days"] = (data.index - data.index[0]).days
        data["Price_Change"] = data["High"] - data["Low"]
        data["Average_Price"] = (data["High"] + data["Low"]) / 2
        data["Daily_Return"] = data["Close"].pct_change()
        data["MA_7"] = data["Close"].rolling(window=7).mean()
        data["Volatility"] = data["Close"].rolling(window=7).std()
        data["Next_Close"] = data["Close"].shift(-1)
        data = data.dropna()
        
        # Özellikler ve hedef
        features = [
            "Days",
            "Open",
            "High",
            "Low",
            "Volume",
            "Price_Change",
            "Average_Price",
            "Daily_Return",
            "MA_7",
            "Volatility",
        ]
        X = data[features]
        y = data["Next_Close"]
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=RANDOM_STATE
        )
        
        # Model eğitimi
        print("⏳ Model eğitiliyor...")
        model = GradientBoostingRegressor(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=RANDOM_STATE
        )
        model.fit(X_train, y_train)
        
        # Model performansı
        y_pred = model.predict(X_test)
        r2 = r2_score(y_test, y_pred)
        print(f"✅ Model eğitildi (R² = {r2:.4f})")
        
        # Gelecek tahmini
        print(f"⏳ {yil} yıl sonrası için tahmin yapılıyor...")
        
        def ileri_tahmin_yap(model, son_satir, kapanis_gecmisi, adim_sayisi):
            """Bir sonraki günü tahmin ederek ileriye doğru iteratif tahmin yap"""
            simulated_row = son_satir.copy()
            closes = list(kapanis_gecmisi)
            predicted_price = float(simulated_row["Close"])

            for _ in range(adim_sayisi):
                feature_row = pd.DataFrame([{
                    "Days": simulated_row["Days"],
                    "Open": simulated_row["Open"],
                    "High": simulated_row["High"],
                    "Low": simulated_row["Low"],
                    "Volume": simulated_row["Volume"],
                    "Price_Change": simulated_row["Price_Change"],
                    "Average_Price": simulated_row["Average_Price"],
                    "Daily_Return": simulated_row["Daily_Return"],
                    "MA_7": simulated_row["MA_7"],
                    "Volatility": simulated_row["Volatility"],
                }])

                predicted_price = float(model.predict(feature_row)[0])
                predicted_price = max(predicted_price, 0.01)

                closes.append(predicted_price)
                rolling_window = closes[-7:]
                mean_close = sum(rolling_window) / len(rolling_window)
                if len(rolling_window) > 1:
                    variance = sum((x - mean_close) ** 2 for x in rolling_window) / (len(rolling_window) - 1)
                    volatility = variance ** 0.5
                else:
                    volatility = 0.0

                previous_close = closes[-2]
                daily_return = ((predicted_price - previous_close) / previous_close) if previous_close else 0.0

                simulated_row["Days"] += 1
                simulated_row["Open"] = previous_close
                simulated_row["High"] = max(previous_close, predicted_price)
                simulated_row["Low"] = min(previous_close, predicted_price)
                simulated_row["Volume"] = simulated_row["Volume"]
                simulated_row["Price_Change"] = simulated_row["High"] - simulated_row["Low"]
                simulated_row["Average_Price"] = (simulated_row["High"] + simulated_row["Low"]) / 2
                simulated_row["Daily_Return"] = daily_return
                simulated_row["MA_7"] = mean_close
                simulated_row["Volatility"] = volatility
                simulated_row["Close"] = predicted_price

            return predicted_price

        last_row = data.iloc[-1].copy()
        future_days = yil * 365
        
        future_price = ileri_tahmin_yap(model, last_row, data["Close"].tail(7).tolist(), future_days)
        current_price = float(data["Close"].iloc[-1])
        change_percentage = ((future_price - current_price) / current_price) * 100
        
        # Hedef tarih
        target_date = datetime.now() + timedelta(days=yil*365)
        
        return {
            "name": name,
            "ticker": ticker,
            "current_price": current_price,
            "future_price": future_price,
            "change_percentage": change_percentage,
            "target_date": target_date,
            "years": yil,
            "r2": r2,
            "data_points": len(data)
        }
        
    except Exception as e:
        print(f"❌ Hata oluştu: {str(e)}")
        return None


def sonuclari_goster(sonuc: dict):
    """Tahmin sonuçlarını göster"""
    if not sonuc:
        return
    
    print("\n" + "="*70)
    print("🎯 TAHMİN SONUÇLARI")
    print("="*70)
    
    print(f"\n📊 Şirket: {sonuc['name']} ({sonuc['ticker']})")
    print(f"📅 Hedef Tarih: {sonuc['target_date'].strftime('%d %B %Y')}")
    print(f"⏰ Tahmin Süresi: {sonuc['years']} yıl")
    
    print(f"\n💰 Güncel Fiyat: {sonuc['current_price']:.4f} TL")
    print(f"🎯 Tahmin Edilen Fiyat: {sonuc['future_price']:.4f} TL")
    
    # Değişim yönü
    if sonuc['change_percentage'] > 0:
        emoji = "📈"
        renk = "YEŞİL"
    else:
        emoji = "📉"
        renk = "KIRMIZI"
    
    print(f"{emoji} Beklenen Değişim: %{sonuc['change_percentage']:+.4f} ({renk})")
    
    # Kazanç/Kayıp hesaplama
    if sonuc['change_percentage'] > 0:
        print(f"\n💵 1000 TL yatırım yaparsanız:")
        kazanc = 1000 * (sonuc['change_percentage'] / 100)
        toplam = 1000 + kazanc
        print(f"   Kazanç: {kazanc:.2f} TL")
        print(f"   Toplam: {toplam:.2f} TL")
    else:
        print(f"\n⚠️  1000 TL yatırım yaparsanız:")
        kayip = 1000 * (abs(sonuc['change_percentage']) / 100)
        toplam = 1000 - kayip
        print(f"   Kayıp: {kayip:.2f} TL")
        print(f"   Kalan: {toplam:.2f} TL")
    
    print(f"\n📊 Model Güvenilirliği (R²): {sonuc['r2']:.4f}")
    print(f"📈 Kullanılan Veri: {sonuc['data_points']} gün")
    
    # Güvenilirlik değerlendirmesi
    if sonuc['r2'] > 0.9:
        guvenilirlik = "Çok Yüksek ✅"
    elif sonuc['r2'] > 0.8:
        guvenilirlik = "Yüksek ✅"
    elif sonuc['r2'] > 0.7:
        guvenilirlik = "Orta ⚠️"
    else:
        guvenilirlik = "Düşük ⚠️"
    
    print(f"🎓 Güvenilirlik Seviyesi: {guvenilirlik}")
    
    print("\n" + "="*70)
    print("⚠️  NOT: Bu tahmin geçmiş verilere dayalıdır ve yatırım tavsiyesi değildir.")
    print("="*70)


def main():
    """Ana fonksiyon"""
    print("\n" + "="*70)
    print("⚡ HIZLI HİSSE SENEDİ TAHMİN ARACI")
    print("="*70)
    print("\nBu araç ile hızlıca bir hisse senedi seçip gelecek tahmini yapabilirsiniz.")
    
    while True:
        # Hisse seç
        name, ticker = hisse_sec()
        
        # Yıl al
        yil = yil_al()
        
        # Onay al
        print(f"\n✅ Seçim: {name} ({ticker}) - {yil} yıl sonrası")
        onay = input("Devam etmek istiyor musunuz? (E/H): ").strip().upper()
        
        if onay != 'E':
            print("❌ İşlem iptal edildi.")
            continue
        
        # Tahmin yap
        sonuc = veri_cek_ve_tahmin_yap(ticker, name, yil)
        
        # Sonuçları göster
        sonuclari_goster(sonuc)
        
        # Tekrar sor
        print("\n" + "="*70)
        tekrar = input("Başka bir tahmin yapmak ister misiniz? (E/H): ").strip().upper()
        
        if tekrar != 'E':
            print("\n👋 Görüşmek üzere!")
            break


if __name__ == "__main__":
    main()

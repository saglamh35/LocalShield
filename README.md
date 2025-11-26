# 🛡️ LocalShield

> **Privacy-First, AI-Powered SIEM & Detection Engineering Platform.**

LocalShield, kişisel bilgisayarınızı bir siber güvenlik kalesine dönüştürür. **AsyncIO** mimarisi ile Windows loglarını gerçek zamanlı izler, **Kural Motoru (Detection Engine)** ile saldırıları anında tespit eder ve **Lokal AI (Ollama)** ile olayları yorumlar.

Verileriniz asla buluta gönderilmez. %100 Yerel ve Çevrimdışı çalışır.

---

## ⚡ Neden LocalShield?

| Özellik | Açıklama |
| :--- | :--- |
| **🧠 Hibrit Zeka** | Hem **AI (Gemma/Llama)** hem de **Kural Tabanlı (YAML)** tespit mekanizması birlikte çalışır. |
| **🚀 Asenkron Mimari** | `AsyncIO` ve `ThreadPool` sayesinde logları sistemi yormadan, milisaniyeler içinde işler. |
| **🎯 MITRE ATT&CK** | Saldırıları endüstri standardı kodlarla (örn: `T1110 - Brute Force`) etiketler. |
| **🛡️ Privacy-First** | İnternet gerekmez. Loglar ve AI analizi tamamen makinenizde (`localhost`) kalır. |
| **📊 SOC Dashboard** | Profesyonel bir SIEM arayüzü ile riskleri, zaman çizelgesini ve portları görselleştirir. |



## 🏗️ Mimari

LocalShield, modern bir **Pipeline** mimarisi kullanır:

1. **Ingestion:** Windows Event Log'ları asenkron olarak okunur.
2. **Detection:**
   * **Reflex:** YAML kuralları ile bilinen saldırılar (Brute Force vb.) anında yakalanır.
   * **Brain:** Bilinmeyen olaylar Local LLM tarafından analiz edilir.
3. **Storage:** SQLite (WAL Modu) ile yüksek performanslı kayıt.
4. **Visualization:** Streamlit tabanlı interaktif dashboard ve AI Asistan.

<img width="2816" height="1536" alt="Gemini_Generated_Image_rmjc5mrmjc5mrmjc" src="https://github.com/user-attachments/assets/3398cb0e-07d8-4d3b-9fe4-e71dcea6518a" />






## 🚀 Hızlı Başlangıç (Quick Start)

### 1. Gereksinimler

* **Ollama** kurulu olmalı (`ollama pull gemma2:2b` veya `llama3.2`)
* **Python 3.10+**
* **Windows 10/11** (Event Log okuma için)
* **Yönetici Hakları** (Log okuma için)

### 2. Kurulum

```bash
git clone https://github.com/YOUR_USERNAME/LocalShield.git
cd LocalShield

# Gerekli değil, başlatma scripti (bat) bunu otomatik yapar ama manuel isterseniz:
pip install -r requirements.txt
```

### 3. Tek Tıkla Başlatma (Windows)

**`run_localshield.bat`** dosyasını çalıştırarak tüm sistemi tek seferde başlatabilirsiniz:

```bash
run_localshield.bat
```

Bu script:
- ✅ Sanal ortamı kontrol eder/aktif eder
- ✅ Bağımlılıkları yükler
- ✅ Log Watcher'ı arka planda başlatır (Yönetici haklarıyla)
- ✅ Dashboard'ı açar

### 4. Manuel Başlatma

#### Log Watcher'ı Başlatın

```bash
python log_watcher.py
```

> ⚠️ **Not**: Log Watcher'ı **yönetici haklarıyla** çalıştırmanız gerekir.

#### Dashboard'ı Açın

Yeni bir terminal penceresinde:

```bash
streamlit run dashboard.py
```

Dashboard otomatik olarak tarayıcıda açılacaktır (varsayılan: `http://localhost:8501`).

---

## 🧪 Saldırı Simülasyonu (Test İçin)

Sistemin çalışıp çalışmadığını test etmek için:

```bash
python simulate_attack.py
```

Veya özelleştirilmiş parametrelerle:

```bash
python simulate_attack.py -n 10 -t 60 -u ATTACKER
```

**Parametreler:**
- `-n, --num-attempts`: Simüle edilecek deneme sayısı (varsayılan: 5)
- `-t, --time-window`: Zaman penceresi saniye cinsinden (varsayılan: 60)
- `-u, --user`: Saldırgan kullanıcı adı (varsayılan: ATTACKER)

---

## 📁 Proje Yapısı

```
LocalShield/
├── dashboard.py              # Streamlit dashboard
├── log_watcher.py            # AsyncIO log watcher
├── db_manager.py             # SQLite veritabanı yönetimi
├── simulate_attack.py        # Saldırı simülasyon aracı
├── config.py                 # Yapılandırma dosyası
├── requirements.txt          # Python bağımlılıkları
├── run_localshield.bat       # Windows başlatma scripti
├── LICENSE                   # MIT License
├── README.md                 # Bu dosya
│
├── modules/                  # Ana modüller
│   ├── ai_engine.py         # AI analiz motoru
│   ├── detection_engine.py  # Kural tabanlı tespit motoru
│   ├── chat_manager.py      # AI asistan modülü
│   ├── network_scanner.py   # Port tarama modülü
│   ├── knowledge_base.py    # Hibrit RAG sistemi
│   └── ai_models.py         # Pydantic modelleri
│
├── rules/                    # YAML detection rules
│   └── *.yaml               # Kural dosyaları
│
├── data/                     # Knowledge base verileri
│   ├── local_knowledge.json
│   └── external_knowledge.json
│
└── tests/                    # Test dosyaları
    └── test_*.py
```

---

## 🔍 Özellikler Detayı

### 1. AsyncIO Mimarisi

Log Watcher, **AsyncIO** kullanarak non-blocking, yüksek performanslı log işleme gerçekleştirir. Bu sayede:
- ✅ Çoklu event'ler paralel işlenir
- ✅ Sistem kaynakları verimli kullanılır
- ✅ Gerçek zamanlı analiz mümkün olur

### 2. Hibrit Analiz Sistemi

**Kural Motoru (Detection Engine)** + **AI Analizi (Brain)** kombinasyonu:

- **Kural Motoru**: Hızlı, kesin tespitler için YAML tabanlı kurallar
- **AI Analizi**: Karmaşık pattern'leri anlamak için Ollama LLM
- **Override Mantığı**: Kural motoru "Yüksek Risk" derse, AI skorunu override eder

### 3. MITRE ATT&CK Entegrasyonu

Tespit edilen olaylar otomatik olarak MITRE ATT&CK teknikleriyle eşleştirilir:
- ✅ Kural motoru MITRE tekniklerini belirler
- ✅ Dashboard'da görsel olarak gösterilir
- ✅ CSV export'ta dahil edilir

### 4. Gerçek Zamanlı Dashboard

Streamlit tabanlı interaktif arayüz:
- 📊 **Log Analizi**: Filtreleme, arama, CSV export
- 🌐 **Ağ Taraması**: Açık port tespiti ve risk analizi
- 💬 **AI Asistan**: Sistem durumu hakkında soru-cevap
- 📈 **Grafikler**: Zaman çizelgesi ve risk dağılımı

---

## ⚙️ Yapılandırma

Yapılandırma dosyası (`config.py`) veya `.env` dosyası üzerinden ayarlanabilir:

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `OLLAMA_MODEL_NAME` | Ollama model adı | `gemma3:4b` |
| `DB_PATH` | Veritabanı dosya yolu | `logs.db` |
| `EVENT_LOG_NAME` | Windows Event Log adı | `Security` |
| `CHECK_INTERVAL` | Log kontrol aralığı (saniye) | `5` |
| `LOG_LEVEL` | Log seviyesi | `INFO` |

---

## 🏗️ Teknoloji Yığını

| Kategori | Teknoloji |
|----------|-----------|
| **Dil** | Python 3.10+ |
| **Web Framework** | Streamlit |
| **AI/ML** | Ollama (Lokal LLM) |
| **Veritabanı** | SQLite (WAL Modu) |
| **Async Runtime** | AsyncIO |
| **Windows Integration** | pywin32 |
| **Data Processing** | Pandas, Altair |
| **Testing** | Pytest |
| **Configuration** | python-dotenv, Pydantic |
| **Rule Engine** | YAML-based Detection Rules |

---

## 🧪 Test

Proje, pytest ile test edilmiştir:

```bash
pytest tests/
```


## 📝 Lisans

Bu proje **MIT License** altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen:
1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

---

## 📧 İletişim

Sorularınız veya önerileriniz için issue açabilirsiniz.

---


<div align="center">

**🛡️ LocalShield ile güvenli kalın! 🛡️**

Made with ❤️ for the cybersecurity community

</div>

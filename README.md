# 🛡️ LocalShield

> **Privacy-First, AI-Powered SIEM & Detection Engineering Platform.**

LocalShield turns your personal computer into a cybersecurity fortress. With an **AsyncIO** architecture it monitors Windows logs in real time, detects attacks instantly via a **Rule Engine (Detection Engine)**, and explains incidents using **Local AI (Ollama)**.

Your data is never sent to the cloud. It runs 100% locally and offline.

---


## ⚡ Why LocalShield?

| Feature                          | Description                                                                                         |
| :------------------------------- | :-------------------------------------------------------------------------------------------------- |
| **🧠 Hybrid Intelligence**       | Combines both **AI (Gemma/Llama)** and **Rule-Based (YAML)** detection mechanisms.                  |
| **🚀 Asynchronous Architecture** | Processes logs within milliseconds using `AsyncIO` and `ThreadPool` without overloading the system. |
| **🎯 MITRE ATT&CK**              | Labels attacks with industry-standard codes (e.g., `T1110 - Brute Force`).                          |
| **🛡️ Privacy-First**            | No internet required. Logs and AI analysis stay entirely on your machine (`localhost`).             |
| **📊 SOC Dashboard**             | Professional SIEM-style UI to visualize risks, timelines, and open ports.                           |

---


## 🏗️ Architecture

LocalShield uses a modern **pipeline** architecture:

1. **Ingestion:** Windows Event Logs are read asynchronously.
2. **Detection:**

   * **Reflex:** Known attacks (e.g., brute force) are instantly caught with YAML rules.
   * **Brain:** Unknown or complex events are analyzed by a local LLM.
3. **Storage:** High-performance logging with SQLite (WAL mode).
4. **Visualization:** Streamlit-based interactive dashboard and AI assistant.

---

<img width="2816" height="1536" alt="Gemini_Generated_Image_rmjc5mrmjc5mrmjc" src="https://github.com/user-attachments/assets/3398cb0e-07d8-4d3b-9fe4-e71dcea6518a" />


## 🚀 Quick Start

### 1. Requirements

* **Ollama** installed (`ollama pull gemma2:2b` or `llama3.2`)
* **Python 3.10+**
* **Windows 10/11** (for Event Log reading)
* **Administrator privileges** (to read Security logs)


### 2. Installation

```bash
git clone https://github.com/YOUR_USERNAME/LocalShield.git
cd LocalShield

# Optional: the startup .bat script can do this automatically,
# but you can also install dependencies manually:
pip install -r requirements.txt
```


### 3. One-Click Start (Windows)

You can start the entire system at once by running **`run_localshield.bat`**:

```bash
run_localshield.bat
```

This script will:

* ✅ Check/activate the virtual environment
* ✅ Install dependencies
* ✅ Start the Log Watcher in the background (with admin rights)
* ✅ Open the dashboard


### 4. Manual Start

#### Start the Log Watcher

```bash
python log_watcher.py
```

> ⚠️ **Note**: You must run the Log Watcher **with administrator privileges**.


#### Start the Dashboard

In a new terminal window:

```bash
streamlit run dashboard.py
```

The dashboard will automatically open in your browser (default: `http://localhost:8501`).

---


## 🧪 Attack Simulation (For Testing)

To test if the system works correctly:

```bash
python simulate_attack.py
```

Or with custom parameters:

```bash
python simulate_attack.py -n 10 -t 60 -u ATTACKER
```

**Parameters:**

* `-n, --num-attempts`: Number of simulated attempts (default: 5)
* `-t, --time-window`: Time window in seconds (default: 60)
* `-u, --user`: Attacker username (default: ATTACKER)

---


## 📁 Project Structure

```text
LocalShield/
├── dashboard.py              # Streamlit dashboard
├── log_watcher.py            # AsyncIO log watcher
├── db_manager.py             # SQLite database manager
├── simulate_attack.py        # Attack simulation tool
├── config.py                 # Configuration file
├── requirements.txt          # Python dependencies
├── run_localshield.bat       # Windows startup script
├── LICENSE                   # MIT License
├── README.md                 # This file
│
├── modules/                  # Core modules
│   ├── ai_engine.py          # AI analysis engine
│   ├── detection_engine.py   # Rule-based detection engine
│   ├── chat_manager.py       # AI assistant module
│   ├── network_scanner.py    # Port scanning module
│   ├── knowledge_base.py     # Hybrid RAG system
│   └── ai_models.py          # Pydantic models
│
├── rules/                    # YAML detection rules
│   └── *.yaml                # Rule files
│
├── data/                     # Knowledge base data
│   ├── local_knowledge.json
│   └── external_knowledge.json
│
└── tests/                    # Test files
    └── test_*.py
```

---


## 🔍 Feature Details

### 1. AsyncIO Architecture

The Log Watcher uses **AsyncIO** for non-blocking, high-performance log processing. This enables:

* ✅ Parallel processing of multiple events
* ✅ Efficient use of system resources
* ✅ Real-time analysis

### 2. Hybrid Analysis System

Combination of **Rule Engine (Detection Engine)** + **AI Analysis (Brain)**:

* **Rule Engine**: YAML-based rules for fast, deterministic detections
* **AI Analysis**: Ollama LLM to understand complex or unknown patterns
* **Override Logic**: If the rule engine marks an event as "High Risk", it overrides the AI score

### 3. MITRE ATT&CK Integration

Detected events are automatically mapped to MITRE ATT&CK techniques:

* ✅ Rule engine assigns MITRE technique IDs
* ✅ Techniques are visualized in the dashboard
* ✅ Included in CSV exports

### 4. Real-Time Dashboard

Streamlit-based interactive UI:

* 📊 **Log Analysis**: Filtering, search, CSV export
* 🌐 **Network Scan**: Open port detection and risk assessment
* 💬 **AI Assistant**: Q&A about system status and events
* 📈 **Charts**: Timeline and risk distribution

---


## ⚙️ Configuration

You can configure LocalShield through the `config.py` file or via a `.env` file:

| Parameter           | Description                    | Default     |
| ------------------- | ------------------------------ | ----------- |
| `OLLAMA_MODEL_NAME` | Ollama model name              | `gemma3:4b` |
| `DB_PATH`           | Database file path             | `logs.db`   |
| `EVENT_LOG_NAME`    | Windows Event Log name         | `Security`  |
| `CHECK_INTERVAL`    | Log polling interval (seconds) | `5`         |
| `LOG_LEVEL`         | Log level                      | `INFO`      |

---


## 🏗️ Tech Stack

| Category                | Technology                 |
| ----------------------- | -------------------------- |
| **Language**            | Python 3.10+               |
| **Web Framework**       | Streamlit                  |
| **AI/ML**               | Ollama (Local LLM)         |
| **Database**            | SQLite (WAL Mode)          |
| **Async Runtime**       | AsyncIO                    |
| **Windows Integration** | pywin32                    |
| **Data Processing**     | Pandas, Altair             |
| **Testing**             | Pytest                     |
| **Configuration**       | python-dotenv, Pydantic    |
| **Rule Engine**         | YAML-based detection rules |

---


## 🧪 Tests

The project is tested with `pytest`:

```bash
pytest tests/
```

---


## 📤 Push to GitHub (Force Push)

If you have previously pushed something to GitHub and now your local state conflicts with it, you might get errors. The following commands treat your local state as the **single source of truth** and overwrite GitHub.

Open a terminal, go to the project directory, and run:

```powershell
# 1. Stage and commit your changes
git add .
git commit -m "Final Release v1.0: Async Architecture, Detection Engine & Dashboard Polish"

# 2. Make sure the branch is named main
git branch -M main

# 3. FORCE PUSH (WARNING: overwrites existing code on GitHub with local state)
git push -u origin main --force
```

> ⚠️ **Warning**: The `--force` flag will completely overwrite the existing code on GitHub. Make sure you really want this before using it!

---


## 📝 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---


## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---


## 📧 Contact

If you have questions or suggestions, feel free to open an issue.

---


## 🙏 Acknowledgements

* **Ollama** – for local LLM support
* **Streamlit** – for the dashboard framework
* **MITRE ATT&CK** – for the reference framework

---

<div align="center">

**🛡️ Stay safe with LocalShield! 🛡️**

Made with ❤️ for the cybersecurity community

</div>

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

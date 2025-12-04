# 🛡️ LocalShield

> **Privacy-First, AI-Powered SIEM & SOAR Platform.**

LocalShield turns your personal computer into a cybersecurity fortress. It's a next-gen security tool that **monitors** Windows logs (Security & Sysmon), **detects** threats using Hybrid Intelligence (AI + Rules), and **responds** instantly by blocking malicious IPs via Windows Firewall.

Your data is never sent to the cloud. It runs 100% locally and offline.

---

## ⚡ Key Capabilities

| Feature                          | Description                                                                                         |
| :------------------------------- | :-------------------------------------------------------------------------------------------------- |
| **🧠 Hybrid Intelligence** | Combines **Local LLM (Ollama)** analysis with deterministic **YAML Rules**.                         |
| **👁️ Deep Visibility (Sysmon)** | Ingests **Sysmon** telemetry (Process Creation, Network Connect) alongside standard Security logs.  |
| **🛡️ Active Response (SOAR)** | Automatically **blocks malicious IPs** in Windows Firewall upon high-confidence detection.          |
| **🌍 Threat Intelligence** | Integrated offline **IOC Matching** engine to instantly detect known bad actors (Botnets, C2).      |
| **🚀 High Performance** | Built on **AsyncIO** architecture to process thousands of events per second without lag.            |
| **🎯 MITRE ATT&CK** | Maps incidents to industry-standard techniques (e.g., `T1110 - Brute Force`).                       |

---

## 🏗️ Architecture

LocalShield uses a sophisticated **Data Pipeline**:

1. **Ingestion:** Asynchronous reading of Windows **Security** and **Sysmon** Event Logs.
2. **Enrichment:** Logs are parsed for `CommandLine`, `Image`, and `User` details.
3. **Detection Layer:**
   * **Threat Intel:** Checks IPs against a local IOC database (O(1) lookup).
   * **Rule Engine:** Executes YAML-based logic (e.g., "5 failed logins in 1 min").
   * **AI Analysis:** Sends complex logs to a Local LLM for context and advice.
4. **Response Layer (SOAR):** If Risk is `High`, the **Firewall Manager** automatically blocks the Source IP.
5. **Visualization:** Streamlit dashboard provides real-time situational awareness.

---
<img width="2816" height="1504" alt="Gemini_Generated_Image_2upsbg2upsbg2ups" src="https://github.com/user-attachments/assets/2d5a3c66-6340-43f6-a80f-6ce65996a8ab" />



## 🚀 Quick Start

### 1. Requirements
* **Ollama** installed (`ollama pull gemma2:2b` or similar)
* **Python 3.10+**
* **Sysmon** installed (Recommended for full visibility)
* **Administrator privileges** (Required for Log Reading & Firewall Management)

### 2. Installation
```bash
git clone [https://github.com/YOUR_USERNAME/LocalShield.git](https://github.com/YOUR_USERNAME/LocalShield.git)
cd LocalShield
# Dependencies are automatically installed by the startup script


### 3. One-Click Start (Windows)

You can start the entire system at once by running **`run_localshield.bat`**:

```bash
run_localshield.bat
```

### 3. One-Click Start (Windows)
Run run_localshield.bat as Administrator. It will:

✅ Set up the Python environment

✅ Start the Log Watcher (Detection & Response Engine)

✅ Launch the SOC Dashboard


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


## 🧪 Simulation & Testing

You can test the system's capabilities using the included tools:

1.  **Brute Force Simulation:**

    ```bash
    python simulate_attack.py
    ```

    *Generates fake failed login attempts to trigger the Rule Engine.*

2.  **Sysmon Test:**
    Open CMD as Administrator and run:

    ```cmd
    whoami /all
    ```

    *Triggers Event ID 1 (Process Creation), visible in the dashboard.*

-----

## 📁 Project Structure

```text
LocalShield/
├── modules/
│   ├── response_engine.py    # SOAR: Firewall Block Logic
│   ├── threat_intel.py       # IOC Matching Engine
│   ├── ai_engine.py          # Local LLM Interface
│   ├── detection_engine.py   # YAML Rule Processor
│   ├── network_scanner.py    # Port Scanner
│   └── log_watcher.py        # Core AsyncIO Loop
├── rules/                    # Detection Logic (YAML)
├── data/                     # Threat Intel Feeds (CSV)
├── dashboard.py              # Streamlit UI
├── config.py                 # Configuration File
├── requirements.txt          # Dependencies
├── LICENSE                   # MIT License
└── run_localshield.bat       # Windows Launcher
```

-----

## 🔍 Feature Details

### 1\. 👁️ Full-Spectrum Visibility (Security + Sysmon)

LocalShield goes beyond standard logging by integrating **Microsoft Sysmon**.

  * **Security Logs:** Tracks logons, privilege escalation, and account management (Event ID 4625, 4672).
  * **Sysmon Telemetry:** Captures deep endpoint activity like Process Creation (Event ID 1) and Network Connections (Event ID 3), enabling detection of complex malware execution chains.

### 2\. 🛡️ Automated Active Response (SOAR)

The system effectively closes the loop between detection and mitigation.

  * **Mechanism:** When a "High Risk" threat (e.g., Brute Force, Known Bad IP) is detected, the **Response Engine** triggers immediately.
  * **Action:** It interacts with the Windows Network Stack to create a dynamic **Firewall Rule**, blocking the attacker's IP address in real-time.
  * **Safety:** Includes safeguards to prevent blocking private/local IPs (e.g., `192.168.x.x`).

### 3\. 🌍 Offline Threat Intelligence

A built-in IOC (Indicator of Compromise) matching engine that requires no internet connection.

  * **Performance:** Uses high-performance Set data structures for **O(1)** lookup speed.
  * **Function:** Instantly flags IPs associated with known Botnets, C2 servers, or attackers before they can harm the system.

### 4\. 🧠 Hybrid Analysis Architecture

Combines three distinct detection layers for maximum accuracy:

  * **Layer 1 (Threat Intel):** Instant check against known bad actors.
  * **Layer 2 (Rule Engine):** Deterministic YAML rules for pattern matching (e.g., MITRE T1110).
  * **Layer 3 (AI Brain):** Local LLM (Ollama) analysis for context-aware interpretation of unknown events.

-----

## ⚙️ Configuration

You can configure LocalShield through the `config.py` file or via a `.env` file:

| Parameter           | Description                                      | Default                              |
| ------------------- | ------------------------------------------------ | ------------------------------------ |
| `OLLAMA_MODEL_NAME` | Ollama model name                                | `gemma3:4b`                          |
| `DB_PATH`           | Database file path                               | `logs.db`                            |
| `EVENT_LOG_NAME`    | Windows Security Log channel                     | `Security`                           |
| `SYSMON_LOG_NAME`   | Sysmon Log channel                               | `Microsoft-Windows-Sysmon/Operational`|
| `CHECK_INTERVAL`    | Log polling interval (seconds)                   | `5`                                  |
| `LOG_LEVEL`         | Application logging level                        | `INFO`                               |

-----

## 🏗️ Tech Stack

| Category                | Technology                 |
| ----------------------- | -------------------------- |
| **Language** | Python 3.10+               |
| **Core Architecture** | AsyncIO (Non-blocking I/O) |
| **Endpoint Telemetry** | **Microsoft Sysmon** |
| **Response Engine** | **Windows Firewall API (Netsh)** |
| **AI/ML** | Ollama (Local LLM)         |
| **Database** | SQLite (WAL Mode)          |
| **Visualization** | Streamlit                  |
| **Data Validation** | Pydantic                   |
| **Rule Engine** | YAML-based detection rules |


-----

## 📝 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.



-----

## 📧 Contact

If you have questions or suggestions, feel free to open an issue.

-----

## 🙏 Acknowledgements

  * **Ollama** – for local LLM support
  * **Streamlit** – for the dashboard framework
  * **MITRE ATT\&CK** – for the reference framework
  * **Microsoft Sysinternals** – for Sysmon

-----







<div align="center">

**🛡️ Stay safe with LocalShield! 🛡️**

Made with ❤️ for the cybersecurity community

</div>


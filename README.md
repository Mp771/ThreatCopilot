# 🛡️ ThreatCopilot – AI-Powered SOC Investigation Assistant

🚀 ThreatCopilot is an AI-powered Security Operations Center (SOC) investigation platform that helps security analysts detect, investigate, and understand security threats through automated detection, MITRE ATT&CK mapping, evidence collection, and AI-assisted analysis.

Built using **FastAPI, Elasticsearch, PostgreSQL, and React**, ThreatCopilot provides an end-to-end workflow for threat detection and incident investigation.

---

## ✨ Features

### 🌐 Network Monitoring

* Capture live network connections
* Collect endpoint network telemetry
* Store events in Elasticsearch
* Monitor network activity in real time

### 🚨 Threat Detection Engine

* Behavioral detection rules
* High Connection Volume detection
* Automated alert generation
* Severity-based classification

### 🔍 Investigation Engine

* Alert investigation workflow
* MITRE ATT&CK mapping
* Evidence collection
* Automated threat summaries
* Analyst recommendations

### 🤖 AI-Assisted Analysis

* Threat explanation generation
* Context-aware investigation summaries
* Analyst-friendly incident insights
* Investigation recommendations

### 📊 Alert Management

* PostgreSQL-backed alert storage
* Investigation history tracking
* Alert retrieval APIs
* Investigation session management

### 💻 SOC Dashboard

* Interactive analyst terminal
* Investigation history panel
* Incident report generation
* Modern cybersecurity-inspired UI

---

## 🏗️ Architecture

```text
                     🌐 Network Traffic
                              │
                              ▼
                    📡 Network Monitor
                              │
                              ▼
                    🔎 Elasticsearch
                              │
                              ▼
                   🚨 Detection Engine
                              │
                              ▼
                   🗄️ PostgreSQL Alerts
                              │
                              ▼
                 🕵️ Investigation Engine
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
     🗺️ MITRE Mapper    📑 Evidence      🤖 AI Analysis
                           Collector
            └─────────────────┼─────────────────┘
                              ▼
                  💻 ThreatCopilot Dashboard
                              │
                              ▼
                    📄 SOC Incident Reports
```

---

## 🛠️ Tech Stack

### Backend ⚙️

* FastAPI
* Python
* Uvicorn

### Databases 🗄️

* PostgreSQL
* Elasticsearch

### Frontend 🎨

* React
* Vite
* Tailwind CSS

### Security 🔐

* MITRE ATT&CK Framework
* Detection Engineering
* Threat Investigation
* Network Monitoring

---

## 📂 Project Structure

```text
backend/
│
├── app/
│   ├── auth/
│   ├── routes/
│   │   ├── auth.py
│   │   ├── history.py
│   │   ├── network.py
│   │   └── logs.py
│   │
│   ├── services/
│   │   ├── network_monitor.py
│   │   ├── detection_engine.py
│   │   ├── alert_service.py
│   │   ├── alert_analyzer.py
│   │   ├── evidence_collector.py
│   │   ├── mitre_mapper.py
│   │   ├── ai_investigator.py
│   │   └── report_generator.py
│   │
│   ├── schemas/
│   ├── db/
│   └── core/
│
└── frontend/
    ├── src/
    │   ├── components/
    │   ├── App.jsx
    │   └── main.jsx
    └── public/
```

---

## 🔄 Investigation Workflow

### 1️⃣ Capture Network Activity

```http
POST /network/capture
```

Collects live network connections and stores them in Elasticsearch.

---

### 2️⃣ Analyze Network Activity

```http
POST /network/analyze
```

Applies detection rules and generates security alerts.

---

### 3️⃣ Retrieve Alerts

```http
GET /network/alerts
```

Fetches alerts stored in PostgreSQL.

---

### 4️⃣ Investigate an Alert

```http
GET /network/investigate/{alert_id}
```

Performs:

✅ Alert Retrieval
✅ MITRE ATT&CK Mapping
✅ Evidence Collection
✅ Threat Analysis
✅ Recommendation Generation

### Example Response

```json
{
  "alert_type": "High Connection Volume",
  "severity": "MEDIUM",
  "mitre_id": "T1046",
  "mitre_name": "Network Service Discovery",
  "tactic": "Discovery",
  "connection_count": 18,
  "summary": "Source IP 8.8.8.8 generated 18 network connections. This activity maps to MITRE ATT&CK T1046.",
  "recommendation": [
    "Review the owning process",
    "Check destination reputation",
    "Investigate related network activity"
  ]
}
```

---

## 🗺️ MITRE ATT&CK Integration

ThreatCopilot maps detected behaviors to MITRE ATT&CK techniques to provide investigation context.

| Alert Type             | Technique                         | Tactic    |
| ---------------------- | --------------------------------- | --------- |
| High Connection Volume | T1046 – Network Service Discovery | Discovery |

---

## 🚀 Getting Started

### 📥 Clone Repository

```bash
git clone https://github.com/Mp771/siem-threat-copilot.git
cd siem-threat-copilot
```

---

### ⚙️ Backend Setup

```bash
cd backend

python -m venv venv

# Windows
venv\Scripts\activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger API Docs:

```text
http://127.0.0.1:8000/docs
```

---

### 🎨 Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend:

```text
http://localhost:5173
```

---

## 📈 Current Capabilities

✅ Network Connection Monitoring
✅ Elasticsearch Integration
✅ Detection Engine
✅ Alert Generation
✅ PostgreSQL Alert Storage
✅ MITRE ATT&CK Mapping
✅ Evidence Collection
✅ Investigation Workflows
✅ Analyst Recommendations
✅ React Dashboard

---

## 🔮 Future Enhancements

* 🚨 Port Scan Detection
* 🔑 Brute Force Detection
* 📡 Beaconing Detection
* 🌍 Threat Intelligence Enrichment
* 🦠 VirusTotal Integration
* 🛑 AbuseIPDB Integration
* ⏱️ Timeline Reconstruction
* 📄 PDF Incident Reports
* 👥 Role-Based Access Control (RBAC)
* 🧠 LLM-Powered Threat Analysis



## 👨‍💻 Author

**Mannat Pal**

🎯 Cybersecurity Enthusiast
🛡️ SOC Analyst & Detection Engineering
🔬 Malware Analysis & Threat Hunting

🔗 GitHub: https://github.com/Mp771

---

⭐ If you found this project useful, consider giving it a star!

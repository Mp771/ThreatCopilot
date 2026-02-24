# 🛡️ ThreatCopilot – AI-Powered SOC Investigation Assistant

ThreatCopilot is an AI-assisted Security Operations Center (SOC) investigation system that enables analysts to query security logs using natural language.
It combines log analytics, NLP parsing, MITRE ATT&CK enrichment, and conversational UI to streamline threat investigation workflows.

---

## 🚀 Features

* Natural language log querying
* Multi-turn conversational context
* Elasticsearch dynamic filtering
* Aggregation for top attackers
* MITRE ATT&CK technique enrichment
* Demo mode for portfolio showcase
* Optional Gemini LLM integration
* Chat-style frontend interface

---

## 🏗️ System Architecture

```
Frontend (Chat UI)
│
▼
FastAPI Backend
│
├── NLP Layer
│   ├── Rule-Based Parser
│   └── Gemini LLM (Optional)
│
├── Session Context Memory
│
├── Elasticsearch Service
│   ├── Search Queries
│   └── Aggregations (Top Attackers)
│
└── MITRE Enrichment Layer
│
▼
Elasticsearch Index (soc-logs)
```

---

## 📂 Project Structure

```
backend/
│
├── app/
│   ├── core/
│   ├── routes/
│   │   └── nlp.py
│   ├── services/
│   │   ├── elastic_service.py
│   │   └── nlp_service.py
│   ├── schemas/
│   └── main.py
│
├── frontend/
├── .env
└── demo_data/
```

---

## ⚙️ Tech Stack

* Python 3.13
* FastAPI
* Elasticsearch 8.x
* Uvicorn
* Gemini API (Optional)
* Vite + Vanilla JavaScript frontend

---

## 🧠 How It Works

1. User submits a natural language query.
2. NLP layer converts it into structured JSON intent.
3. Event normalization ensures schema alignment.
4. Elasticsearch DSL query is generated.
5. Results are enriched with MITRE ATT&CK techniques.
6. Structured summary is returned to the frontend.

---

## 🔍 Example Queries

```
Show failed VPN logins
Show brute force attempts more than 2
Show SSH failures yesterday
Show malware detected events
```

---

## 🛠️ Installation

### 1️⃣ Clone Repository

```
git clone https://github.com/your-username/threatcopilot.git
cd threatcopilot/backend
```

### 2️⃣ Create Virtual Environment

**Windows**

```
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**

```
python3 -m venv venv
source venv/bin/activate
```

### 3️⃣ Install Dependencies

```
pip install -r requirements.txt
```

### 4️⃣ Setup `.env`

```
ELASTIC_URL=http://localhost:9200
INDEX_NAME=soc-logs
USE_GEMINI=false
DEMO_MODE=true
GEMINI_API_KEY=your_key_if_needed
```

### 5️⃣ Run Backend

```
uvicorn app.main:app --reload
```

### 6️⃣ Run Frontend

```
cd frontend
npm install
npm run dev
```

---

## 🧪 Demo Mode

If `DEMO_MODE=true`:

* Time filters disabled
* Static demo dataset used
* Ideal for GitHub demos and portfolio showcase

---

## 🤖 Optional Gemini LLM Integration

Enable LLM parsing:

```
USE_GEMINI=true
GEMINI_API_KEY=your_key
```

Model used:

```
gemini-2.5-flash
```

If disabled, system falls back to rule-based parsing.

---

## 🎯 MITRE ATT&CK Mapping

| Event Type       | MITRE Technique        |
| ---------------- | ---------------------- |
| failure          | T1110 – Brute Force    |
| malware_detected | T1204 – User Execution |

---

## 📊 Sample Output

```
3 events detected involving 1 unique IP address(es).

MITRE: T1110 – Brute Force
```

---

## 🔐 Security Considerations

* Keyword fields used for Elasticsearch aggregations
* Fielddata disabled to avoid memory overhead
* API keys stored via environment variables
* Demo mode prevents dependency on live logs

---

## 📌 Future Enhancements

* Severity scoring engine
* Risk scoring model
* Timeline visualization
* Anomaly detection module
* Automated SOC report generation
* Security dashboard

---

## 👨‍💻 Author

AI-powered SOC automation prototype built for security analytics, threat investigation, and intelligent log analysis workflows.

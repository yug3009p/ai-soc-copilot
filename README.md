# 🛡️ AI-SOC Copilot

> AI-assisted security alert triage: paste a raw alert, get a structured first-pass analysis with severity, MITRE ATT&CK mapping, recommended actions and Splunk SPL hunt queries.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-red?style=flat-square&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-gpt--oss--120b-F55036?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Screenshots

<img src="screenshots/01-dashboard.png" alt="AI-SOC Copilot main dashboard" width="100%">

*Privilege escalation sample: the alert input with the structured analysis beside it. All four screenshots are real runs of the bundled samples (November 2026, `openai/gpt-oss-120b`).*

<img src="screenshots/02-lateral-movement.png" alt="Lateral movement alert analysis" width="100%">

*Lateral movement analysis — AI triage of a Windows lateral movement alert with MITRE mapping and remediation steps.*

<img src="screenshots/03-dns-exfiltration.png" alt="DNS exfiltration alert analysis" width="100%">

*DNS exfiltration analysis — detection of data exfiltration via DNS tunneling with severity rating and SPL queries.*

<img src="screenshots/04-brute-force.png" alt="Brute force alert analysis" width="100%">

*Brute force analysis — credential brute force triage with blocked IP recommendations and Splunk investigation queries.*

---

## Why This Project

SOC analysts receive far more alerts than they can investigate in depth. Triage means manually cross-referencing event codes, looking up MITRE ATT&CK mappings, writing investigation queries and documenting findings: repetitive work that slows response.

This alert fatigue leads to:
- Critical threats buried under noise
- Analyst burnout and high turnover
- Slower mean-time-to-respond (MTTR)
- Inconsistent triage quality across skill levels

**AI-SOC Copilot** is a first-pass assistant for that work: paste a raw alert and get a structured analysis to review. The analyst still makes the call; the tool drafts the lookups, mappings and queries.

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit |
| AI Engine | `openai/gpt-oss-120b` on Groq by default; set `GROQ_MODEL` in `.env` to use another Groq model |
| SDK | `groq` Python SDK |
| Config | `python-dotenv` |
| Language | Python 3.11+ |
| History | Local `analyses.json` |

**Speed:** a sample alert took about 3 seconds end to end in testing (one run, November 2026); it depends on the model and Groq's load.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/yug3009p/ai-soc-copilot.git
cd ai-soc-copilot
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure your API key

```bash
cp .env.example .env
```

Open `.env` and add your [Groq API key](https://console.groq.com/keys):

```
GROQ_API_KEY=gsk_...
```

### 5. Run the app

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`.

---

## Example Usage

**Input alert** (paste into the text area):

```
2024-01-15 14:23:42 EventCode=4625 Account=administrator Domain=CORP
Failure_Reason="Bad password" Source_IP=203.0.113.45
[50 similar events in 16 seconds]
2024-01-15 14:23:58 EventCode=4740 Account=administrator (ACCOUNT LOCKED OUT)
```

**AI output** (illustrative; LLM responses vary between runs):

| Field | Result |
|---|---|
| **Severity** | 🔴 Critical |
| **Summary** | An external IP (203.0.113.45) launched a credential brute-force attack against the domain controller, targeting the built-in administrator account. 50 failed logon attempts in 16 seconds triggered an account lockout. |
| **MITRE** | T1110.001 — Brute Force: Password Guessing (Credential Access) |
| **Actions** | Block 203.0.113.45 at perimeter firewall; investigate for successful logons; check all locked accounts; review DC event logs for EventCode=4624 post-lockout |
| **SPL Query** | `index=wineventlog EventCode=4625 src_ip=203.0.113.45 \| timechart span=1s count` |

---

## Evaluation

There is no formal evaluation yet. LLM output can be wrong, so treat every result as a draft for an analyst to verify. For example, a model may claim an IP has a bad reputation even though the app performs no threat-intel lookups. A labeled evaluation set that measures severity and ATT&CK-mapping accuracy is on the roadmap.

What is tested today (`pytest`, run in CI on Ubuntu and Windows) is the code around the model: parsing and validating its JSON, falling back safely when it returns an unexpected severity, escaping its output before rendering, and the analysis history.

## Security notes

- The alert text you paste is sent to Groq. Do not paste logs you are not allowed to share with a third party.
- Alerts are untrusted data and can carry prompt injection. The prompt tells the model not to follow instructions in the alert, and everything the model returns is HTML-escaped before display.
- See [SECURITY.md](SECURITY.md) to report a vulnerability.

---

## Project Structure

```
ai-soc-copilot/
├── app.py               # Main Streamlit application
├── tests/               # pytest suite for the non-LLM logic
├── .github/workflows/   # CI: lint + tests
├── requirements.txt     # Python dependencies
├── requirements-dev.txt # pytest, ruff
├── .env.example         # API key template
├── .gitignore
├── LICENSE
├── README.md
├── SECURITY.md · CONTRIBUTING.md · CHANGELOG.md
├── screenshots/
└── sample_alerts/
    ├── brute_force_login.txt
    ├── dns_exfiltration.txt
    ├── privilege_escalation.txt
    └── lateral_movement.txt
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Yug Mukesh Patel**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/yugpatel9409/)

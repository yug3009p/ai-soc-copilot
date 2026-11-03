# Contributing

Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/yug3009p/ai-soc-copilot.git
cd ai-soc-copilot
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```

The tests do not call the LLM and need no API key. CI runs them on Ubuntu and Windows.

## Guidelines

- Treat both the alert and the model's reply as untrusted: validate the reply with
  `normalize_analysis()` and pass every model-provided string through `html.escape` before
  rendering it with `unsafe_allow_html=True`.
- Add a sample alert to `sample_alerts/` for any new alert type, using synthetic data and
  documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Do not add accuracy or time-saving claims to the README without a reproducible evaluation.

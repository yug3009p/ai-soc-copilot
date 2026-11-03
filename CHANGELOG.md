# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Groq retired `llama-3.3-70b-versatile`, so every analysis failed with "model not found". The model
  is now configurable (`GROQ_MODEL`, default `openai/gpt-oss-120b`), with room for reasoning tokens.
- Screenshots retaken from real runs of all four samples; the old dashboard screenshot paired one
  alert with another alert's result.

### Security
- Model output (summary, reasoning, actions, technique fields, severity) is now HTML-escaped before
  rendering. Streamlit already strips event handlers, so this was not script execution, but raw
  HTML such as fake links could be injected through a crafted alert.
- The prompt now tells the model to treat the alert as untrusted data.

### Fixed
- A severity outside Critical/High/Medium/Low crashed the results panel; replies are now validated
  by `normalize_analysis()` and unknown severities shown as "Unknown".
- The sidebar listed VirusTotal, Shodan, AbuseIPDB and other "Intel Sources" that the app never
  queries. It now lists only the frameworks the analysis maps to.
- Removed unverified metrics from the README, and an example-output detail (an AbuseIPDB score) that
  the README's example input did not contain (earlier PR).

### Added
- pytest suite for the non-LLM logic, CI on Ubuntu and Windows, SECURITY.md, CONTRIBUTING.md,
  this changelog.

## [1.0.0] - 2026-05-13

Not tagged; refers to the first version on `main`.

### Added
- Streamlit triage app: paste an alert, get severity, summary, ATT&CK mapping, actions and an SPL
  query from Llama 3.3 70B via Groq.

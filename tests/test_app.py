"""Tests for the parts of the app that do not call the LLM."""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402


@pytest.fixture
def history_file(tmp_path, monkeypatch):
    path = tmp_path / "analyses.json"
    monkeypatch.setattr(app, "ANALYSES_FILE", path)
    return path


GOOD = {
    "summary": "Brute force against administrator.",
    "severity": "critical",
    "severity_reasoning": "50 failures then lockout.",
    "mitre_techniques": [
        {"technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access",
         "relevance": "Repeated 4625 events."}
    ],
    "recommended_actions": ["Block the source IP", "Reset the account"],
    "spl_query": "index=wineventlog EventCode=4625",
}


def test_parse_plain_and_fenced_json():
    raw = json.dumps(GOOD)
    assert app.parse_llm_json(raw) == GOOD
    assert app.parse_llm_json(f"```json\n{raw}\n```") == GOOD
    assert app.parse_llm_json(f"```\n{raw}") == GOOD  # missing closing fence


def test_parse_rejects_non_objects():
    with pytest.raises(ValueError):
        app.parse_llm_json("[1, 2, 3]")
    with pytest.raises(json.JSONDecodeError):
        app.parse_llm_json("not json")


def test_normalize_fixes_case_and_keeps_fields():
    out = app.normalize_analysis(GOOD)
    assert out["severity"] == "Critical"
    assert out["mitre_techniques"][0]["technique_id"] == "T1110.001"
    assert out["recommended_actions"] == GOOD["recommended_actions"]


def test_normalize_handles_off_schema_output():
    out = app.normalize_analysis(
        {"severity": "Informational", "mitre_techniques": ["T1078", None], "recommended_actions": None}
    )
    assert out["severity"] == "Unknown"
    assert out["mitre_techniques"] == []
    assert out["recommended_actions"] == []
    assert out["summary"] == "No summary available."
    # Every severity the UI can receive has a full style entry (an unknown one used to crash).
    assert {"color", "border", "glow", "cls"} <= app.SEVERITY_CONFIG[out["severity"]].keys()


def test_severity_badge_escapes_model_text():
    badge = app.render_severity_badge('<img src=x onerror="alert(1)">')
    assert "<img" not in badge
    assert "&lt;img" in badge


def test_header_stats_counts_today_only():
    today = datetime.now().isoformat()
    history = [
        {"timestamp": "2020-01-01T00:00:00", "analysis": {"severity": "Critical"}},
        {"timestamp": today, "analysis": {"severity": "Critical"}},
        {"timestamp": today, "analysis": {"severity": "Low"}},
    ]
    stats = app.get_header_stats(history)
    assert stats["total_today"] == 2
    assert stats["criticals_today"] == 1
    assert app.get_header_stats([])["last_analyzed"] == "—"


def test_history_round_trip_and_corrupt_file(history_file):
    assert app.load_history() == []
    app.save_analysis("alert text", GOOD)
    assert app.load_history()[0]["alert_text"] == "alert text"
    history_file.write_text("{not json", encoding="utf-8")
    assert app.load_history() == []


def test_sample_alerts_load_with_readable_names():
    samples = app.load_sample_alerts()
    assert "DNS Exfiltration" in samples
    assert all(text.strip() for text in samples.values())


def test_prompt_treats_alert_as_untrusted():
    assert "untrusted data" in app.SYSTEM_PROMPT


def test_model_is_configurable(monkeypatch):
    import importlib

    monkeypatch.setenv("GROQ_MODEL", "some/other-model")
    reloaded = importlib.reload(app)
    assert reloaded.GROQ_MODEL == "some/other-model"
    monkeypatch.delenv("GROQ_MODEL")
    assert importlib.reload(app).GROQ_MODEL == "openai/gpt-oss-120b"

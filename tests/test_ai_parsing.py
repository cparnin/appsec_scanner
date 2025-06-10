import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.ai.remediation import batch_suggest_remediation


def test_batch_parsing_no_index_error(monkeypatch):
    # Prepare a fake OpenAI API response with incomplete numbered line
    responses = [
        {
            "choices": [
                {"message": {"content": "1\n2. fix second"}}
            ]
        }
    ]
    call_count = 0

    def fake_post(url, headers, json, timeout):
        nonlocal call_count
        call_count += 1
        class Resp:
            def raise_for_status(self):
                pass
            def json(self):
                return responses[call_count-1]
        return Resp()

    monkeypatch.setattr("src.ai.remediation.requests.post", fake_post)
    monkeypatch.setenv("OPENAI_API_KEY", "test")

    findings = [{"description": "a"}, {"description": "b"}]
    batch_suggest_remediation(findings, batch_size=2)

    # No IndexError occurred and at least one suggestion parsed correctly
    assert any(f.get("ai_remediation", "").startswith("fix second") for f in findings)

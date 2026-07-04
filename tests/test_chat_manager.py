"""
Unit tests for chat_manager: system-summary building from the DB and the
assistant call (Ollama mocked, so no live model / network needed).
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import config
import db_manager
from modules import chat_manager


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    path = str(tmp_path / "chat.db")
    db_manager.init_db(path)
    monkeypatch.setattr(config, "DB_PATH", path)
    # Force deterministic demo ports (offline, no psutil scan variance)
    monkeypatch.setattr(config, "DEMO_MODE", True)
    return path


class TestSystemSummary:
    def test_includes_high_risk_logs(self, temp_db):
        db_manager.insert_log(
            datetime.now(), "4625", "failed logon 1.2.3.4", "analysis", "High", "T1110", db_path=temp_db
        )
        summary = chat_manager.get_system_summary()
        assert "HIGH RISK LOGS" in summary
        assert "4625" in summary

    def test_no_high_risk_is_stated(self, temp_db):
        db_manager.insert_log(datetime.now(), "4624", "normal", "ok", "Low", None, db_path=temp_db)
        summary = chat_manager.get_system_summary()
        assert "No high-risk logs found" in summary


class TestAskAssistant:
    def test_returns_model_answer(self, temp_db, monkeypatch):
        captured = {}

        def fake_chat(**kwargs):
            captured["messages"] = kwargs["messages"]
            return {"message": {"content": "• All clear."}}

        monkeypatch.setattr(chat_manager._client, "chat", fake_chat)
        answer = chat_manager.ask_assistant("Any risks?")
        assert "All clear" in answer
        # The system prompt must be grounded in the live system data
        assert "SYSTEM DATA" in captured["messages"][0]["content"]

    def test_model_error_is_handled(self, temp_db, monkeypatch):
        def boom(**kwargs):
            raise RuntimeError("model down")

        monkeypatch.setattr(chat_manager._client, "chat", boom)
        answer = chat_manager.ask_assistant("Any risks?")
        assert "error occurred" in answer.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

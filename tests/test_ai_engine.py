"""
Unit tests for Brain (ai_engine): response caching and Ollama JSON mode.
ollama.chat is patched so no real model is needed.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import ai_engine
from modules.ai_engine import Brain

VALID_JSON = '{"risk_score":"High","user_entity":"ATTACKER","summary":"s","advice":"a"}'


@pytest.fixture
def counting_chat(monkeypatch):
    """Patch ollama.Client so Brain's timeout-configured client returns canned JSON."""
    calls = []

    def fake_chat(**kwargs):
        calls.append(kwargs)
        return {"message": {"content": VALID_JSON}}

    class FakeClient:
        def __init__(self, *a, **k):
            pass
        chat = staticmethod(fake_chat)

    monkeypatch.setattr(ai_engine.ollama, "Client", FakeClient)
    return calls


class TestBrain:
    def test_uses_json_format(self, counting_chat):
        brain = Brain()
        md, risk = brain.analyze("Event ID: 4625\nMessage: failed logon")
        assert risk == "High"
        assert counting_chat[0].get("format") == "json"

    def test_identical_event_is_cached(self, counting_chat):
        brain = Brain()
        # Same content, only the timestamp differs -> must hit the cache
        brain.analyze("Event ID: 4625\nTime: 2020-01-01 00:00:00\nMessage: failed logon")
        brain.analyze("Event ID: 4625\nTime: 2999-12-31 23:59:59\nMessage: failed logon")
        assert len(counting_chat) == 1, "second identical event should be served from cache"

    def test_different_event_calls_model_again(self, counting_chat):
        brain = Brain()
        brain.analyze("Event ID: 4625\nMessage: failed logon")
        brain.analyze("Event ID: 4624\nMessage: successful logon")
        assert len(counting_chat) == 2

    def test_cache_is_bounded(self, counting_chat):
        brain = Brain()
        brain._cache_max = 3
        for i in range(10):
            brain.analyze(f"Event ID: {1000 + i}\nMessage: unique {i}")
        assert len(brain._cache) <= 3

    def test_timeout_falls_back_to_medium(self, monkeypatch):
        """A hung/slow model (client raises) must degrade to a Medium fallback, not propagate."""
        class TimeoutClient:
            def __init__(self, *a, **k):
                pass
            def chat(self, **kwargs):
                raise TimeoutError("model timed out")

        monkeypatch.setattr(ai_engine.ollama, "Client", TimeoutClient)
        brain = Brain()
        md, risk = brain.analyze("Event ID: 4625\nMessage: failed logon")
        assert risk == "Medium"
        assert md  # a non-empty fallback explanation is returned


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Unit tests for the KnowledgeBase (hybrid RAG): local/external lookup and the
external->internal normalization.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.knowledge_base import KnowledgeBase


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase()


class TestLookup:
    def test_local_knowledge_loaded(self, kb):
        assert len(kb.local_knowledge) > 0

    def test_known_local_event(self, kb):
        info = kb.get_event_info("4624")
        assert info is not None
        assert info["source"] == "local"
        assert "risk_level" in info and "advice" in info

    def test_unknown_event_returns_none(self, kb):
        assert kb.get_event_info("999999") is None

    def test_event_id_is_normalized_to_string(self, kb):
        # Passing an int should still resolve
        assert kb.get_event_info(4624) is not None


class TestNormalizeExternal:
    def test_error_level_is_high(self, kb):
        n = kb._normalize_external_info({"name": "X", "description": "d", "level": "error"})
        assert n["risk_level"] == "High"

    def test_information_level_is_low(self, kb):
        n = kb._normalize_external_info({"name": "X", "level": "information"})
        assert n["risk_level"] == "Low"

    def test_security_recommendation_is_high(self, kb):
        n = kb._normalize_external_info({"name": "X", "securityMonitoringRecommandation": "yes, monitor"})
        assert n["risk_level"] == "High"

    def test_advice_prefers_explicit_field(self, kb):
        n = kb._normalize_external_info({"name": "X", "advice": "do this"})
        assert n["advice"] == "do this"

    def test_title_falls_back(self, kb):
        n = kb._normalize_external_info({"eventID": "1234", "description": "d"})
        assert "1234" in n["title"] or n["title"]  # some non-empty title

    def test_non_dict_input_is_safe(self, kb):
        n = kb._normalize_external_info("not a dict")
        assert n["risk_level"] == "Medium"  # default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

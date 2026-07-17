"""
Tests for correlation-state persistence: prior events survive an engine
restart, are consumed on fire, and stale rows get pruned.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from db_manager import init_db
from modules.correlation_store import CorrelationStore
from modules.detection_engine import DetectionEngine

RULES_DIR = str(Path(__file__).parent.parent / "rules")


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "corr.db")
    init_db(path).close()
    return path


@pytest.fixture
def store(db_path):
    return CorrelationStore(db_path)


def _fail(ip):
    return f"An account failed to log on.\n\tSource Network Address:\t{ip}\n"


def _success(ip):
    return f"An account was successfully logged on.\n\tSource Network Address:\t{ip}\n"


class TestCorrelationStore:
    def test_record_and_load_round_trip(self, store):
        now = datetime.now()
        store.record_prior("rule_a", "1.2.3.4", now)
        store.record_prior("rule_a", "1.2.3.4", now + timedelta(seconds=1))
        store.record_prior("rule_a", "5.6.7.8", now)

        priors = store.load_priors("rule_a", now - timedelta(seconds=60))
        assert set(priors.keys()) == {"1.2.3.4", "5.6.7.8"}
        assert len(priors["1.2.3.4"]) == 2

    def test_load_honors_cutoff(self, store):
        now = datetime.now()
        store.record_prior("rule_a", "1.2.3.4", now - timedelta(seconds=600))
        store.record_prior("rule_a", "1.2.3.4", now)

        priors = store.load_priors("rule_a", now - timedelta(seconds=300))
        assert len(priors.get("1.2.3.4", [])) == 1

    def test_load_is_scoped_to_rule(self, store):
        now = datetime.now()
        store.record_prior("rule_a", "1.2.3.4", now)
        store.record_prior("rule_b", "1.2.3.4", now)

        assert "1.2.3.4" in store.load_priors("rule_a", now - timedelta(seconds=60))
        assert len(store.load_priors("rule_c", now - timedelta(seconds=60))) == 0

    def test_clear_key_removes_only_that_rule_and_key(self, store):
        now = datetime.now()
        store.record_prior("rule_a", "1.2.3.4", now)
        store.record_prior("rule_a", "5.6.7.8", now)
        store.record_prior("rule_b", "1.2.3.4", now)

        store.clear_key("rule_a", "1.2.3.4")

        cutoff = now - timedelta(seconds=60)
        assert "1.2.3.4" not in store.load_priors("rule_a", cutoff)
        assert "5.6.7.8" in store.load_priors("rule_a", cutoff)
        assert "1.2.3.4" in store.load_priors("rule_b", cutoff)

    def test_prune_deletes_old_rows_and_returns_count(self, store):
        now = datetime.now()
        store.record_prior("rule_a", "1.2.3.4", now - timedelta(hours=2))
        store.record_prior("rule_a", "1.2.3.4", now - timedelta(hours=3))
        store.record_prior("rule_a", "5.6.7.8", now)

        removed = store.prune(now - timedelta(hours=1))
        assert removed == 2

        priors = store.load_priors("rule_a", now - timedelta(days=1))
        assert set(priors.keys()) == {"5.6.7.8"}

    def test_missing_db_is_swallowed(self, tmp_path):
        # No init_db: every call must fail soft, never raise.
        broken = CorrelationStore(str(tmp_path / "missing" / "nope.db"))
        broken.record_prior("r", "k", datetime.now())
        broken.clear_key("r", "k")
        assert broken.load_priors("r", datetime.now()) == {}
        assert broken.prune(datetime.now()) == 0


class TestEngineRestartPersistence:
    def test_correlation_state_survives_restart(self, db_path):
        """4 failures before a 'restart', the 5th after: the fresh engine must
        still correlate and fire on the subsequent success."""
        base = datetime.now()
        ip = "203.0.113.77"

        engine_a = DetectionEngine(rules_dir=RULES_DIR, store=CorrelationStore(db_path))
        for i in range(4):
            engine_a.check_event("4625", base + timedelta(seconds=i), _fail(ip), "Security")

        # "Restart": a brand-new engine over the same database.
        engine_b = DetectionEngine(rules_dir=RULES_DIR, store=CorrelationStore(db_path))
        engine_b.check_event("4625", base + timedelta(seconds=5), _fail(ip), "Security")
        result = engine_b.check_event("4624", base + timedelta(seconds=6), _success(ip), "Security")

        assert result is not None
        assert result["rule_id"] == "brute_force_success_001"

    def test_fire_consumes_persisted_priors(self, db_path):
        """After the rule fires, a third engine must not re-fire on a lone
        success: the persisted priors were consumed."""
        base = datetime.now()
        ip = "203.0.113.88"

        engine_a = DetectionEngine(rules_dir=RULES_DIR, store=CorrelationStore(db_path))
        for i in range(5):
            engine_a.check_event("4625", base + timedelta(seconds=i), _fail(ip), "Security")
        fired = engine_a.check_event("4624", base + timedelta(seconds=6), _success(ip), "Security")
        assert fired is not None and fired["rule_id"] == "brute_force_success_001"

        engine_c = DetectionEngine(rules_dir=RULES_DIR, store=CorrelationStore(db_path))
        again = engine_c.check_event("4624", base + timedelta(seconds=7), _success(ip), "Security")
        if again is not None:
            assert again["rule_id"] != "brute_force_success_001"

    def test_without_store_state_is_memory_only(self, db_path):
        """Default (store=None) keeps the old behavior: nothing is persisted."""
        base = datetime.now()
        ip = "203.0.113.99"

        engine_a = DetectionEngine(rules_dir=RULES_DIR)
        for i in range(5):
            engine_a.check_event("4625", base + timedelta(seconds=i), _fail(ip), "Security")

        # Nothing was written for the correlation rule.
        assert CorrelationStore(db_path).load_priors("brute_force_success_001", base - timedelta(hours=1)) == {}

        # A fresh memory-only engine has forgotten the failures.
        engine_b = DetectionEngine(rules_dir=RULES_DIR)
        result = engine_b.check_event("4624", base + timedelta(seconds=6), _success(ip), "Security")
        if result is not None:
            assert result["rule_id"] != "brute_force_success_001"

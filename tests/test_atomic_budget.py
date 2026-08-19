"""Tests du Atomic Budget Manager (v3.4)."""
import time
import threading
import pytest

try:
    from budget import AtomicBudgetManager, BudgetExceededException
    BUDGET_AVAILABLE = True
except ImportError:
    BUDGET_AVAILABLE = False


@pytest.mark.skipif(not BUDGET_AVAILABLE, reason="budget module not installed")
class TestAtomicBudgetBasic:
    """Tests de base du budget manager."""
    
    def test_initial_state(self):
        """État initial : 0 dépensé."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        assert mgr.get_spent("org1") == 0.0
        assert mgr.get_remaining("org1") == 10.0
    
    def test_reserve_reduces_remaining(self):
        """Une réservation réduit le budget restant."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        res = mgr.reserve("org1", estimated_cost=2.5, trace_id="t1")
        assert res is not None
        assert mgr.get_remaining("org1") == 7.5
    
    def test_reserve_over_budget_fails(self):
        """Une réservation qui dépasse le budget retourne None."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        res1 = mgr.reserve("org1", estimated_cost=8.0)
        assert res1 is not None
        res2 = mgr.reserve("org1", estimated_cost=3.0)
        assert res2 is None  # 8 + 3 = 11 > 10
    
    def test_reconcile_with_actual_cost(self):
        """La réconciliation ajuste au coût réel."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        res = mgr.reserve("org1", estimated_cost=2.0)
        # Actual cost is less than estimated
        mgr.reconcile(res, actual_cost=1.0)
        assert abs(mgr.get_spent("org1") - 1.0) < 0.001
    
    def test_reconcile_with_higher_cost(self):
        """Si actual > estimated, le budget est débité du surplus."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        res = mgr.reserve("org1", estimated_cost=2.0)
        mgr.reconcile(res, actual_cost=3.5)
        assert abs(mgr.get_spent("org1") - 3.5) < 0.001
    
    def test_rollback_releases_budget(self):
        """Un rollback libère la réservation."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        res = mgr.reserve("org1", estimated_cost=5.0)
        assert mgr.get_remaining("org1") == 5.0
        mgr.rollback(res)
        assert mgr.get_remaining("org1") == 10.0


@pytest.mark.skipif(not BUDGET_AVAILABLE, reason="budget module not installed")
class TestAtomicBudgetConcurrency:
    """Tests de concurrence (le vrai test de l'atomicité)."""
    
    def test_concurrent_reservations_no_overshoot(self):
        """
        CRITIQUE : 100 réservations concurrentes de $0.20 sur un budget de $10
        ne doivent PAS dépasser $10 au total.
        
        C'est LE test qui justifie l'existence du Atomic Budget Manager.
        """
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        
        results = {"success": 0, "rejected": 0}
        lock = threading.Lock()
        
        def try_reserve():
            res = mgr.reserve("org1", estimated_cost=0.20)
            with lock:
                if res is not None:
                    results["success"] += 1
                else:
                    results["rejected"] += 1
        
        # Lance 100 threads en parallèle
        threads = [threading.Thread(target=try_reserve) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Vérifie : total réservé <= budget max
        total_reserved = results["success"] * 0.20
        assert total_reserved <= 10.001, f"Budget overshot: {total_reserved} > 10.0"
        # Vérifie : on a bien rejeté les réservations en trop
        assert results["success"] <= 50  # 50 × $0.20 = $10
        assert results["success"] + results["rejected"] == 100
    
    def test_race_between_reserve_and_reconcile(self):
        """Une reservation + reconcile concurrentes ne corrompent pas le budget."""
        mgr = AtomicBudgetManager(redis_url=None, max_budget_per_session=10.0)
        
        reservations = []
        for i in range(10):
            res = mgr.reserve("org1", estimated_cost=0.5)
            if res:
                reservations.append(res)
        
        # Réconcilie tous avec actual = estimated
        for res in reservations:
            mgr.reconcile(res, actual_cost=0.5)
        
        # Total devrait être exactement len(reservations) * 0.5
        expected = len(reservations) * 0.5
        assert abs(mgr.get_spent("org1") - expected) < 0.001


@pytest.mark.skipif(not BUDGET_AVAILABLE, reason="budget module not installed")
class TestAtomicBudgetMultiScope:
    """Tests des scopes session + daily."""
    
    def test_daily_budget_separate(self):
        """Le budget daily est indépendant du session."""
        mgr = AtomicBudgetManager(
            redis_url=None,
            max_budget_per_session=5.0,
            max_budget_per_day=50.0,
        )
        mgr.reserve("org1", estimated_cost=4.0)
        
        # Session : reste $1
        assert mgr.get_remaining("org1", "session") == 1.0
        # Daily : reste $46
        assert mgr.get_remaining("org1", "daily") == 46.0
    
    def test_daily_limit_enforced(self):
        """La limite daily est respectée même si session OK."""
        mgr = AtomicBudgetManager(
            redis_url=None,
            max_budget_per_session=100.0,
            max_budget_per_day=5.0,  # petit daily
        )
        res1 = mgr.reserve("org1", estimated_cost=4.0)
        assert res1 is not None
        res2 = mgr.reserve("org1", estimated_cost=2.0)
        assert res2 is None  # Daily dépassé : 4 + 2 = 6 > 5
    
    def test_get_status_complete(self):
        """get_status retourne une vue complète."""
        mgr = AtomicBudgetManager(
            redis_url=None,
            max_budget_per_session=10.0,
            max_budget_per_day=100.0,
        )
        mgr.reserve("org1", estimated_cost=3.0)
        status = mgr.get_status("org1")
        
        assert status["org_id"] == "org1"
        assert status["session"]["max"] == 10.0
        assert status["session"]["spent"] == 3.0
        assert status["session"]["remaining"] == 7.0
        assert status["daily"]["max"] == 100.0
        assert status["daily"]["spent"] == 3.0

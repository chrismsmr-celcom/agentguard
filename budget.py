"""
AgentGuard Atomic Budget Manager
Prévient les race conditions sur le budget via Redis transactions.

Architecture :
  RESERVE → EXECUTE → RECONCILE

Utilise Redis INCRBYFLOAT pour atomicité garantie.
Fallback en mémoire si Redis indisponible (mode dev).
"""
import os
import time
import threading
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class BudgetReservation:
    """Réservation de budget atomique."""
    reservation_id: str
    amount_reserved: float
    reserved_at: float
    expires_at: float
    org_id: str
    trace_id: str
    reconciled: bool = False
    actual_cost: float = 0.0


class AtomicBudgetManager:
    """
    Gestionnaire de budget avec réservations atomiques.
    
    Usage :
        mgr = AtomicBudgetManager(redis_url="redis://...", max_budget=10.0)
        
        # Avant l'appel LLM
        reservation = mgr.reserve(org_id="org1", estimated_cost=0.01, trace_id="t1")
        if not reservation:
            raise BudgetExceededException("No budget remaining")
        
        try:
            result = call_llm()
            actual_cost = compute_cost(result)
            mgr.reconcile(reservation, actual_cost)
        except Exception:
            mgr.rollback(reservation)
            raise
    """
    
    # Clé Redis pour stocker le budget consommé par org
    KEY_PREFIX = "ag:budget:"
    # TTL des réservations non reconciliées (protection anti-leak)
    RESERVATION_TTL = 300  # 5 minutes
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        max_budget_per_session: float = 10.0,
        max_budget_per_day: float = 100.0,
    ):
        self.max_per_session = max(0.0, float(max_budget_per_session))
        self.max_per_day = max(0.0, float(max_budget_per_day))
        
        self._redis = None
        self._memory_lock = threading.Lock()
        self._memory_spent: Dict[str, float] = {}  # org_id -> spent
        self._memory_reservations: Dict[str, BudgetReservation] = {}
        
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url, socket_timeout=2.0)
                self._redis.ping()
            except Exception as e:
                print(f"[BudgetManager] Redis unavailable, using memory fallback: {e}")
                self._redis = None
    
    def _redis_key(self, org_id: str, scope: str = "session") -> str:
        """Clé Redis pour un org et un scope donné."""
        if scope == "daily":
            day = time.strftime("%Y-%m-%d")
            return f"{self.KEY_PREFIX}{org_id}:daily:{day}"
        return f"{self.KEY_PREFIX}{org_id}:session"
    
    def _reservation_key(self, reservation_id: str) -> str:
        return f"{self.KEY_PREFIX}reservation:{reservation_id}"
    
    def get_spent(self, org_id: str, scope: str = "session") -> float:
        """Retourne le montant déjà dépensé (réservations incluses)."""
        if self._redis:
            key = self._redis_key(org_id, scope)
            try:
                val = self._redis.get(key)
                return float(val) if val else 0.0
            except Exception:
                return 0.0
        else:
            with self._memory_lock:
                mem_key = f"{org_id}:{scope}"
                return self._memory_spent.get(mem_key, 0.0)
    
    def get_remaining(self, org_id: str, scope: str = "session") -> float:
        """Retourne le budget restant."""
        spent = self.get_spent(org_id, scope)
        max_budget = self.max_per_session if scope == "session" else self.max_per_day
        return max(0.0, max_budget - spent)
    
    def reserve(
        self,
        org_id: str,
        estimated_cost: float,
        trace_id: str = "",
    ) -> Optional[BudgetReservation]:
        """
        Réserve atomiquement un montant du budget.
        Retourne None si budget insuffisant.
        """
        if estimated_cost <= 0:
            estimated_cost = 0.001  # Minimum pour éviter les divisions par 0
        
        reservation_id = f"res_{int(time.time_ns())}_{os.urandom(4).hex()}"
        
        # Vérifie les deux scopes : session ET daily
        for scope, max_b in [("session", self.max_per_session), ("daily", self.max_per_day)]:
            if self._redis:
                key = self._redis_key(org_id, scope)
                try:
                    # Pipeline atomique : GET + INCRBYFLOAT + vérif
                    pipe = self._redis.pipeline(transaction=True)
                    pipe.get(key)
                    pipe.incrbyfloat(key, estimated_cost)
                    results = pipe.execute()
                    
                    current = float(results[0]) if results[0] else 0.0
                    new_total = float(results[1])
                    
                    if new_total > max_b:
                        # Rollback : décrémenter
                        self._redis.incrbyfloat(key, -estimated_cost)
                        return None
                except Exception as e:
                    print(f"[BudgetManager] Redis error during reserve: {e}")
                    # Fallback mémoire
                    return self._reserve_memory(org_id, estimated_cost, trace_id, reservation_id)
            else:
                # Mode mémoire uniquement
                return self._reserve_memory(org_id, estimated_cost, trace_id, reservation_id)
        
        # Réservation OK : on la stocke pour reconciliation future
        reservation = BudgetReservation(
            reservation_id=reservation_id,
            amount_reserved=estimated_cost,
            reserved_at=time.time(),
            expires_at=time.time() + self.RESERVATION_TTL,
            org_id=org_id,
            trace_id=trace_id,
        )
        
        if self._redis:
            try:
                import json
                self._redis.setex(
                    self._reservation_key(reservation_id),
                    self.RESERVATION_TTL,
                    json.dumps({
                        "amount": estimated_cost,
                        "org_id": org_id,
                        "trace_id": trace_id,
                    }),
                )
            except Exception:
                pass
        else:
            with self._memory_lock:
                self._memory_reservations[reservation_id] = reservation
        
        return reservation
    
    def _reserve_memory(
        self, org_id: str, amount: float, trace_id: str, reservation_id: str
    ) -> Optional[BudgetReservation]:
        """Réservation en mode mémoire (fallback)."""
        with self._memory_lock:
            session_key = f"{org_id}:session"
            daily_key = f"{org_id}:daily"
            
            session_spent = self._memory_spent.get(session_key, 0.0)
            daily_spent = self._memory_spent.get(daily_key, 0.0)
            
            if session_spent + amount > self.max_per_session:
                return None
            if daily_spent + amount > self.max_per_day:
                return None
            
            self._memory_spent[session_key] = session_spent + amount
            self._memory_spent[daily_key] = daily_spent + amount
            
            reservation = BudgetReservation(
                reservation_id=reservation_id,
                amount_reserved=amount,
                reserved_at=time.time(),
                expires_at=time.time() + self.RESERVATION_TTL,
                org_id=org_id,
                trace_id=trace_id,
            )
            self._memory_reservations[reservation_id] = reservation
            return reservation
    
    def reconcile(self, reservation: BudgetReservation, actual_cost: float) -> bool:
        """
        Réconcilie la réservation avec le coût réel.
        Ajuste le budget si actual_cost != reserved.
        """
        if reservation.reconciled:
            return True
        
        actual_cost = max(0.0, float(actual_cost))
        diff = actual_cost - reservation.amount_reserved
        
        if self._redis:
            try:
                for scope in ("session", "daily"):
                    key = self._redis_key(reservation.org_id, scope)
                    if diff != 0:
                        self._redis.incrbyfloat(key, diff)
                # Supprime la réservation
                self._redis.delete(self._reservation_key(reservation.reservation_id))
            except Exception as e:
                print(f"[BudgetManager] Redis error during reconcile: {e}")
                return False
        else:
            with self._memory_lock:
                if reservation.reservation_id in self._memory_reservations:
                    for scope in ("session", "daily"):
                        mem_key = f"{reservation.org_id}:{scope}"
                        current = self._memory_spent.get(mem_key, 0.0)
                        self._memory_spent[mem_key] = current + diff
                    del self._memory_reservations[reservation.reservation_id]
        
        reservation.reconciled = True
        reservation.actual_cost = actual_cost
        return True
    
    def rollback(self, reservation: BudgetReservation) -> bool:
        """Annule une réservation (ex: LLM call a échoué)."""
        if reservation.reconciled:
            return True
        
        if self._redis:
            try:
                for scope in ("session", "daily"):
                    key = self._redis_key(reservation.org_id, scope)
                    self._redis.incrbyfloat(key, -reservation.amount_reserved)
                self._redis.delete(self._reservation_key(reservation.reservation_id))
            except Exception as e:
                print(f"[BudgetManager] Redis error during rollback: {e}")
                return False
        else:
            with self._memory_lock:
                if reservation.reservation_id in self._memory_reservations:
                    for scope in ("session", "daily"):
                        mem_key = f"{reservation.org_id}:{scope}"
                        current = self._memory_spent.get(mem_key, 0.0)
                        self._memory_spent[mem_key] = max(0.0, current - reservation.amount_reserved)
                    del self._memory_reservations[reservation.reservation_id]
        
        reservation.reconciled = True
        return True
    
    def get_status(self, org_id: str) -> Dict:
        """Statut complet du budget pour un org."""
        return {
            "org_id": org_id,
            "session": {
                "max": self.max_per_session,
                "spent": self.get_spent(org_id, "session"),
                "remaining": self.get_remaining(org_id, "session"),
            },
            "daily": {
                "max": self.max_per_day,
                "spent": self.get_spent(org_id, "daily"),
                "remaining": self.get_remaining(org_id, "daily"),
            },
            "redis_available": self._redis is not None,
        }


class BudgetExceededException(Exception):
    """Exception levée quand le budget est dépassé."""
    pass

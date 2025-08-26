from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import exp, log
from typing import Any, Dict, List, Tuple, Optional
import json

from .supabase_client import get_supabase


@dataclass
class FeatureHit:
    key: str
    base: float
    occurred_at: datetime
    critical: bool = False
    details: Dict[str, Any] | None = None


@dataclass
class RiskProfile:
    wallet: str
    risk_score: int
    risk_band: str
    risk_factors: List[str]
    confidence: float
    last_updated: datetime
    transaction_count: int
    total_volume_usd: float
    suspicious_patterns: List[str]


# Enterprise Risk Factor Categories
RISK_CATEGORIES = {
    "SANCTIONS": {
        "weight": 100,
        "description": "OFAC, UN, EU sanctions",
        "half_life_days": 365,
        "critical": True
    },
    "MIXER_TUMBLER": {
        "weight": 85,
        "description": "Privacy tools and mixing services",
        "half_life_days": 180,
        "critical": True
    },
    "DEX_ANONYMITY": {
        "weight": 70,
        "description": "Anonymous DEX usage",
        "half_life_days": 90,
        "critical": False
    },
    "HIGH_VALUE": {
        "weight": 60,
        "description": "Large transaction amounts",
        "half_life_days": 30,
        "critical": False
    },
    "VELOCITY": {
        "weight": 55,
        "description": "Rapid transaction patterns",
        "half_life_days": 14,
        "critical": False
    },
    "CONTRACT_INTERACTION": {
        "weight": 50,
        "description": "Smart contract interactions",
        "half_life_days": 60,
        "critical": False
    },
    "MULTI_CHAIN": {
        "weight": 45,
        "description": "Cross-chain activity",
        "half_life_days": 45,
        "critical": False
    },
    "BEHAVIORAL": {
        "weight": 40,
        "description": "Unusual behavior patterns",
        "half_life_days": 30,
        "critical": False
    },
    "REPUTATION": {
        "weight": 35,
        "description": "Known bad actor associations",
        "half_life_days": 90,
        "critical": False
    },
    "GEOGRAPHIC": {
        "weight": 30,
        "description": "High-risk jurisdictions",
        "half_life_days": 60,
        "critical": False
    }
}


def _calculate_transaction_risk(value_eth: float, gas_price_gwei: float, 
                               data_size: int, is_contract: bool) -> float:
    """Calculate risk based on transaction characteristics"""
    risk = 0.0
    
    # Value-based risk (exponential)
    if value_eth > 0:
        risk += min(50.0, log(max(1.0, value_eth)) * 10)
    
    # Gas price risk (suspicious pricing)
    if gas_price_gwei > 1000:  # Very high gas
        risk += 20.0
    elif gas_price_gwei < 1:  # Suspiciously low
        risk += 15.0
    
    # Contract interaction risk
    if is_contract and data_size > 0:
        risk += min(30.0, data_size / 1000 * 10)
    
    return risk


def _detect_suspicious_patterns(transactions: List[Dict]) -> List[str]:
    """Detect suspicious transaction patterns"""
    patterns = []
    
    if len(transactions) < 3:
        return patterns
    
    # Rapid transactions
    if len(transactions) >= 10:
        time_span = (transactions[-1]['timestamp'] - transactions[0]['timestamp']).total_seconds()
        if time_span < 3600:  # Less than 1 hour
            patterns.append("rapid_transactions")
    
    # Round amounts
    round_amounts = sum(1 for tx in transactions if tx.get('value', 0) % 1 == 0)
    if round_amounts > len(transactions) * 0.7:
        patterns.append("round_amounts")
    
    # Small amounts (dusting)
    dust_count = sum(1 for tx in transactions if tx.get('value', 0) < 0.001)
    if dust_count > len(transactions) * 0.5:
        patterns.append("dusting_attack")
    
    return patterns


def _calculate_network_risk(associated_addresses: List[str], 
                           known_bad_actors: List[str]) -> float:
    """Calculate risk based on network associations"""
    risk = 0.0
    
    # Association with known bad actors
    bad_actor_matches = sum(1 for addr in associated_addresses if addr in known_bad_actors)
    if bad_actor_matches > 0:
        risk += min(40.0, bad_actor_matches * 20)
    
    # Network density (too many connections can be suspicious)
    if len(associated_addresses) > 100:
        risk += min(30.0, (len(associated_addresses) - 100) / 10)
    
    return risk


def _decay(weight: float, occurred_at: datetime, half_life_days: int) -> float:
    """Apply time-based decay to risk weights"""
    age_days = max(0.0, (datetime.now(timezone.utc) - occurred_at.astimezone(timezone.utc)).total_seconds() / 86400.0)
    return weight * exp(-(age_days / max(1.0, float(half_life_days))))


def _soft_cap(sum_weights: float) -> float:
    """Apply soft cap to prevent scores from exceeding 100"""
    return 100.0 * (1.0 - exp(-(sum_weights / 100.0)))


def band_for_score(score: float) -> str:
    """Convert numerical score to risk band"""
    if score >= 100.0:
        return "PROHIBITED"
    elif score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "HIGH"
    elif score >= 40.0:
        return "MEDIUM"
    elif score >= 20.0:
        return "ELEVATED"
    else:
        return "LOW"


def compute_risk_score(hits: List[FeatureHit], sanctions_match: bool,
                       transaction_context: Optional[Dict] = None,
                       network_context: Optional[Dict] = None,
                       half_life_overrides: Dict[str, int] | None = None) -> Tuple[int, str, List[str], List[Tuple[str, int]]]:
    """
    Enhanced risk scoring with enterprise features
    
    Args:
        hits: List of risk feature hits
        sanctions_match: Whether address matches sanctions list
        transaction_context: Transaction details for context-aware scoring
        network_context: Network/graph analysis context
        half_life_overrides: Custom half-life overrides
    
    Returns:
        (score, band, reasons, contributions)
    """
    # Immediate sanctions block
    if sanctions_match:
        return 100, "PROHIBITED", ["SANCTIONS: Address found in sanctioned wallets list"], [("sanctions_match", 100)]
    
    # Initialize scoring
    total_risk = 0.0
    reasons: List[str] = []
    contributions: List[Tuple[str, int]] = []
    critical_factors = []
    
    # Process feature hits with time decay
    for hit in hits:
        category = next((cat for cat in RISK_CATEGORIES.keys() if hit.key.startswith(cat)), "BEHAVIORAL")
        category_config = RISK_CATEGORIES.get(category, RISK_CATEGORIES["BEHAVIORAL"])
        
        # Apply time decay
        half_life = (half_life_overrides or {}).get(hit.key, category_config["half_life_days"])
        decayed_weight = _decay(hit.base, hit.occurred_at, half_life)
        
        # Apply category-specific adjustments
        if category_config["critical"]:
            decayed_weight = max(decayed_weight, 50.0)  # Critical factors maintain minimum weight
            critical_factors.append(hit.key)
        
        # Cap individual factor contribution
        decayed_weight = min(decayed_weight, category_config["weight"])
        
        total_risk += decayed_weight
        applied_weight = int(round(decayed_weight))
        contributions.append((hit.key, applied_weight))
        
        # Generate human-readable reason
        if hit.details:
            reason = f"+{applied_weight} {hit.key} ({_summarize_details(hit.details)})"
        else:
            reason = f"+{applied_weight} {hit.key}"
        reasons.append(reason)
    
    # Add transaction context risk
    if transaction_context:
        tx_risk = _calculate_transaction_risk(
            transaction_context.get('value_eth', 0.0),
            transaction_context.get('gas_price_gwei', 0.0),
            transaction_context.get('data_size', 0),
            transaction_context.get('is_contract', False)
        )
        total_risk += tx_risk
        if tx_risk > 0:
            reasons.append(f"+{int(tx_risk)} transaction_context")
            contributions.append(("transaction_context", int(tx_risk)))
    
    # Add network risk
    if network_context:
        network_risk = _calculate_network_risk(
            network_context.get('associated_addresses', []),
            network_context.get('known_bad_actors', [])
        )
        total_risk += network_risk
        if network_risk > 0:
            reasons.append(f"+{int(network_risk)} network_associations")
            contributions.append(("network_associations", int(network_risk)))
    
    # Apply soft cap
    final_score = _soft_cap(total_risk)
    
    # Critical factor override
    if critical_factors:
        final_score = max(final_score, 80.0)
        reasons.append("CRITICAL: Critical risk factors detected")
    
    # Convert to integer and determine band
    score_int = int(round(final_score))
    band = band_for_score(score_int)
    
    return score_int, band, reasons, contributions


def _summarize_details(details: Dict[str, Any]) -> str:
    """Summarize feature details for human readability"""
    parts: List[str] = []
    for k, v in details.items():
        if isinstance(v, float):
            parts.append(f"{k}={v:.2f}")
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def create_risk_profile(wallet: str, score: int, band: str, 
                       reasons: List[str], confidence: float = 0.8) -> RiskProfile:
    """Create a comprehensive risk profile"""
    return RiskProfile(
        wallet=wallet.lower(),
        risk_score=score,
        risk_band=band,
        risk_factors=reasons,
        confidence=confidence,
        last_updated=datetime.now(timezone.utc),
        transaction_count=0,  # Would be populated from database
        total_volume_usd=0.0,  # Would be populated from database
        suspicious_patterns=[]  # Would be populated from pattern analysis
    )


# Enhanced persistence helpers
def log_risk_events(wallet: str, hits: List[FeatureHit], applied: List[Tuple[str, int]]) -> None:
    """Log risk events to database for audit trail"""
    sb = get_supabase()
    rows: List[Dict[str, Any]] = []
    
    for hit, (key, weight_applied) in zip(hits, applied):
        rows.append({
            "wallet": wallet.lower(),
            "feature": key,
            "details": hit.details or {},
            "weight_applied": weight_applied,
            "timestamp": hit.occurred_at.isoformat()
        })
    
    if rows:
        try:
            sb.table("risk_events").insert(rows).execute()
        except Exception as e:
            print(f"Warning: Failed to log risk events: {e}")


def upsert_risk_score(wallet: str, score: int, band: str, 
                     reasons: List[str] = None, confidence: float = 0.8) -> None:
    """Update risk score in database with enhanced metadata"""
    sb = get_supabase()
    try:
        data = {
            "wallet": wallet.lower(),
            "score": score,
            "band": band
        }
        sb.table("risk_scores").upsert(data).execute()
    except Exception as e:
        print(f"Warning: Failed to upsert risk score: {e}")


def get_risk_profile(wallet: str) -> Optional[RiskProfile]:
    """Retrieve comprehensive risk profile from database"""
    sb = get_supabase()
    try:
        # Get risk score
        score_res = sb.table("risk_scores").select("*").eq("wallet", wallet.lower()).limit(1).execute()
        score_data = score_res.data[0] if score_res.data else None
        
        if not score_data:
            return None
        
        # Get recent risk events
        events_res = sb.table("risk_events").select("*").eq("wallet", wallet.lower()).order("timestamp", desc=True).limit(50).execute()
        events = events_res.data or []
        
        # Get transaction stats (would need additional table)
        # This is a placeholder for future enhancement
        
        return RiskProfile(
            wallet=wallet.lower(),
            risk_score=score_data.get("score", 0),
            risk_band=score_data.get("band", "LOW"),
            risk_factors=[],  # Not stored in current schema
            confidence=0.8,  # Default confidence
            last_updated=datetime.now(timezone.utc),  # Use current time
            transaction_count=0,  # Placeholder
            total_volume_usd=0.0,  # Placeholder
            suspicious_patterns=[]  # Placeholder
        )
    except Exception as e:
        print(f"Warning: Failed to get risk profile: {e}")
        return None

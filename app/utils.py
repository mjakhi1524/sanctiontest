from datetime import datetime, timezone
from pydantic import BaseModel

class Decision(BaseModel):
	allowed: bool
	risk_band: str
	risk_score: int
	reasons: list[str] = []


def decision_from(sanctioned: bool, score: int, band: str) -> Decision:
	if sanctioned:
		return Decision(allowed=False, risk_score=100, risk_band="PROHIBITED", reasons=["OFAC match (sanctioned_wallets)"])
	if band in {"CRITICAL", "HIGH"} or score >= 80:
		return Decision(allowed=False, risk_score=score, risk_band=band, reasons=["High risk score threshold"])
	return Decision(allowed=True, risk_score=score, risk_band=band, reasons=[])


def now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()

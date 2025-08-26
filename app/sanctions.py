from __future__ import annotations

from typing import Tuple

from .supabase_client import get_supabase


class SanctionsChecker:
	async def load_initial(self) -> None:
		return None

	async def is_sanctioned(self, address: str) -> bool:
		addr = (address or "").lower()
		sb = get_supabase()
		res = sb.table("sanctioned_wallets").select("address").eq("address", addr).limit(1).execute()
		rows = res.data or []
		return bool(rows)

	async def get_risk(self, address: str) -> Tuple[int, str]:
		addr = (address or "").lower()
		sb = get_supabase()
		res = sb.table("risk_scores").select("score,band").eq("wallet", addr).limit(1).execute()
		rows = res.data or []
		if not rows:
			return 0, "LOW"
		data = rows[0]
		score = round(data.get("score") or 0)
		band = data.get("band") or "LOW"
		return score, band

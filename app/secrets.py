import os
import logging
from typing import Optional
from .supabase_client import get_supabase

logger = logging.getLogger(__name__)

def get_secret(secret_name: str, env_var: Optional[str] = None) -> Optional[str]:
	"""Get a secret value from env first, then Supabase 'secrets' table as fallback.
	Supabase table schema expected: secrets(key text primary key, value text not null)
	"""
	# 1) Environment variable wins
	if env_var:
		val = os.getenv(env_var)
		if val:
			return val
	# Also try direct name as env
	val = os.getenv(secret_name)
	if val:
		return val
	
	# 2) Supabase fallback
	try:
		sb = get_supabase()
		res = sb.table("secrets").select("value").eq("key", secret_name).limit(1).execute()
		rows = res.data or []
		if rows:
			return rows[0].get("value")
	except Exception as e:
		logger.warning(f"Failed to read secret '{secret_name}' from Supabase: {e}")
	return None

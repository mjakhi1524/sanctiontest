import os
from supabase import create_client, Client

_client: Client | None = None


def get_supabase() -> Client:
	global _client
	if _client is None:
		url = os.getenv("SUPABASE_URL")
		key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
		if not url or not key:
			raise RuntimeError("Missing Supabase configuration")
		_client = create_client(url, key)
	return _client

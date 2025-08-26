import argparse
import json
from typing import Iterable

from app.supabase_client import get_supabase


def read_addresses(path: str) -> list[str]:
	if path.lower().endswith(".json"):
		with open(path, "r", encoding="utf-8") as f:
			data = json.load(f)
			if isinstance(data, list):
				return [str(x).lower() for x in data]
			raise ValueError("JSON must be a list of addresses")
	else:
		out: list[str] = []
		with open(path, "r", encoding="utf-8") as f:
			for line in f:
				addr = line.strip()
				if addr:
					out.append(addr.lower())
		return out


def chunked(items: Iterable[str], size: int = 1000):
	batch: list[str] = []
	for it in items:
		batch.append(it)
		if len(batch) >= size:
			yield batch
			batch = []
	if batch:
		yield batch


def upsert(addresses: list[str], source: str = "OFAC") -> int:
	sb = get_supabase()
	total = 0
	for batch in chunked(addresses, 1000):
		rows = [{"address": a, "source": source} for a in batch]
		sb.table("sanctioned_wallets").upsert(rows, on_conflict="address").execute()
		total += len(batch)
	return total


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--file", required=True, help="Path to JSON or TXT file with addresses")
	parser.add_argument("--source", default="OFAC")
	args = parser.parse_args()

	addrs = read_addresses(args.file)
	count = upsert(addrs, source=args.source)
	print(f"Upserted {count} addresses from {args.file}")


if __name__ == "__main__":
	main()

## Relay API (FastAPI)

FastAPI service that exposes AML-aware relay endpoints backed by Supabase for auth, sanctions, risk and audit logs.

### Endpoints
- POST `/v1/check` — preflight AML decision (no broadcast)
- POST `/v1/relay` — enforced relay; blocks if high risk/sanctioned, else broadcasts

Both endpoints accept optional `features` (evidence array) for on-the-fly risk computation using the risk model.

### Request/Response

`POST /v1/check`
```json
{
  "chain": "ethereum",
  "to": "0xDest",
  "from": "0xSender",
  "value": "120000000",
  "asset": "USDC",
  "features": [
    {
      "key": "mixer_direct",
      "base": 40,
      "occurredAt": "2025-08-15T12:00:00Z",
      "critical": true,
      "details": { "counterparty": "0xTornado...", "valueUSD": 30000 }
    }
  ]
}
```
Response
```json
{
  "allowed": false,
  "risk_band": "CRITICAL",
  "risk_score": 82,
  "reasons": ["+38 mixer_direct (counterparty=0xTornado..., valueUSD=30000)", "+20 wallet_age_lt_7d (ageDays=3)"]
}
```

`POST /v1/relay`
```json
{
  "chain": "ethereum",
  "rawTx": "0x02f8...",
  "idempotencyKey": "...",
  "features": [ { "key": "value_gt_10k", "base": 10, "occurredAt": "2025-08-19T10:00:00Z" } ]
}
```
Response (allowed)
```json
{ "allowed": true, "risk_band": "LOW", "risk_score": 12, "txHash": "0xabc...", "reasons": [] }
```

### File map

- `relay-api/requirements.txt` — Python dependencies
- `relay-api/README.md` — this guide
- `relay-api/ingest_sanctions.py` — CLI to upsert daily JSON/TXT sanctioned addresses into `sanctioned_wallets`
- `relay-api/app/__init__.py` — exports for easier imports
- `relay-api/app/main.py` — FastAPI app and endpoints (`/v1/check`, `/v1/relay`), Supabase auth, logging; integrates risk model with optional `features`
- `relay-api/app/supabase_client.py` — creates Supabase client using env vars
- `relay-api/app/sanctions.py` — sanctioned check and cached risk lookup from Supabase tables
- `relay-api/app/tx_decode.py` — decode raw EVM transaction to extract `to` address (legacy and typed txs)
- `relay-api/app/utils.py` — decision model and helpers
- `relay-api/app/risk_model.py` — risk scoring engine (time decay, soft cap, bands, critical guardrails) and persistence helpers to `risk_events` and `risk_scores`

### Environment
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `RPC_URL_ETHEREUM` (and optionally `RPC_URL_POLYGON`, `RPC_URL_ARBITRUM`, `RPC_URL_OPTIMISM`)

### Local run
```bash
cd relay-api
python -m venv .venv && . .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### Ingest sanctioned lists (daily JSON/TXT)
```bash
python ingest_sanctions.py --file path/to/sanctioned_addresses_ETH.json --source OFAC
# or
python ingest_sanctions.py --file path/to/sanctioned_addresses_ETH.txt --source OFAC
```

TXT: one address per line. JSON: array of addresses. Addresses are lowercased during upsert.

### Notes
- If `features` are provided, the service computes risk on-the-fly, logs `risk_events`, and upserts `risk_scores`.
- If `features` are omitted, the service uses cached `risk_scores` from Supabase and only checks sanctions.
- All decisions are recorded to `relay_logs` with reasons for explainability.

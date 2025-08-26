import os
import logging
from typing import Optional, Dict, List, Any, Tuple

from fastapi import FastAPI, Header, HTTPException, Depends, Security
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, ConfigDict
from web3 import Web3

from .supabase_client import get_supabase
from .local_sanctions import local_sanctions_checker
from .tx_decode import extract_to_address, is_hex_string
from .utils import Decision, decision_from, now_iso
from .risk_model import FeatureHit, compute_risk_score, log_risk_events, upsert_risk_score
from .wallet_risk_assessor import WalletRiskAssessor
from .audit_logger import SanctionsAuditLogger
from .confirmation_system import confirmation_system
from .models import (
    SanctionsManageRequest, SanctionsResponse, WalletRiskAssessmentRequest, 
    WalletRiskAssessmentResponse, SanctionsAuditLog
)
from .secrets import get_secret


class FeatureHitIn(BaseModel):
	key: str
	base: float
	occurredAt: str
	critical: Optional[bool] = False
	details: Optional[dict[str, Any]] = None

	model_config = ConfigDict(extra="ignore")

	def to_domain(self) -> FeatureHit:
		# occurredAt expected as ISO 8601
		from datetime import datetime
		from datetime import timezone as tz
		occurred_at = datetime.fromisoformat(self.occurredAt.replace("Z", "+00:00")).astimezone(tz.utc)
		return FeatureHit(
			key=self.key,
			base=float(self.base),
			occurred_at=occurred_at,
			critical=bool(self.critical),
			details=self.details or {},
		)


class CheckRequest(BaseModel):
	chain: str = Field(default="ethereum")
	to: str
	from_addr: Optional[str] = Field(default=None, alias="from")
	value: Optional[str] = None
	asset: Optional[str] = None
	features: Optional[List[FeatureHitIn]] = None

	# Provide Swagger example so the UI is pre-filled with valid data
	model_config = ConfigDict(
		populate_by_name=True,
		json_schema_extra={
			"example": {
				"chain": "ethereum",
				"to": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
				"from": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
				"value": "1000000000000000000",
				"asset": "ETH",
				"features": [
					{ "key": "value_gt_10k", "base": 10, "occurredAt": "2025-08-21T10:00:00Z" }
				]
			}
		}
	)


class RelayRequest(BaseModel):
	chain: str = Field(default="ethereum")
	rawTx: str
	idempotencyKey: Optional[str] = None
	features: Optional[List[FeatureHitIn]] = None

	model_config = ConfigDict(
		json_schema_extra={
			"example": {
				"chain": "ethereum",
				"rawTx": "0x02f86b01843b9aca00847735940082520894b60e8dd61c5d32be8058bb8eb970870f07233155080c080a0...",
				"idempotencyKey": "example-key-123",
				"features": [ { "key": "value_gt_10k", "base": 10, "occurredAt": "2025-08-21T10:00:00Z" } ]
			}
		}
	)


class RelayResponse(BaseModel):
	allowed: bool
	risk_band: str
	risk_score: int
	txHash: Optional[str] = None
	reasons: Optional[List[str]] = None
	status: Optional[str] = None


class SanctionedWalletRequest(BaseModel):
	address: str = Field(..., description="Wallet address to add/remove from sanctions list")
	action: str = Field(..., description="Action: 'add' or 'remove'")

	model_config = ConfigDict(
		json_schema_extra={
			"example": {
				"address": "0x1234567890123456789012345678901234567890",
				"action": "add"
			}
		}
	)


class SanctionedWalletResponse(BaseModel):
	success: bool
	message: str
	address: str
	action: str
	total_count: int


## (Removed auxiliary models for deleted endpoints)


app = FastAPI(
    title="Relay API", 
    version="1.2.0",
    openapi_tags=[{"name": "default", "description": "Relay API endpoints"}]
)

# CORS for frontend
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8080")
origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]
allow_credentials = os.getenv("ALLOW_CORS_CREDENTIALS", "false").lower() == "true"
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Configure OpenAPI security scheme for Swagger UI
app.openapi_schema = None  # Force regeneration
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version="3.0.2",
        description="Relay API for blockchain risk assessment and transaction relay",
        routes=app.routes,
    )
    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "API Key"
        }
    }
    # Apply security to all endpoints
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
w3_clients: Dict[str, Web3] = {}
wallet_risk_assessor = WalletRiskAssessor()
audit_logger = SanctionsAuditLogger()

def get_w3(chain: str) -> Web3:
	key = chain.lower()
	if key not in w3_clients:
		# chain key → env var name
		mapping = {
			"ethereum": "RPC_URL_ETHEREUM",
			"eth": "RPC_URL_ETHEREUM",
			"sepolia": "RPC_URL_SEPOLIA",
			"polygon": "RPC_URL_POLYGON",
			"matic": "RPC_URL_POLYGON",
			"arbitrum": "RPC_URL_ARBITRUM",
			"arb": "RPC_URL_ARBITRUM",
			"optimism": "RPC_URL_OPTIMISM",
			"base": "RPC_URL_BASE",
			"zksync": "RPC_URL_ZKSYNC",
			"linea": "RPC_URL_LINEA",
			"scroll": "RPC_URL_SCROLL",
			"immutable": "RPC_URL_IMMUTABLE",
			"taiko": "RPC_URL_TAIKO",
			"bsc": "RPC_URL_BSC",
			"binance-smart-chain": "RPC_URL_BSC",
			"avalanche": "RPC_URL_AVALANCHE",
			"avax": "RPC_URL_AVALANCHE",
			"fantom": "RPC_URL_FANTOM",
			"ftm": "RPC_URL_FANTOM",
			"gnosis": "RPC_URL_GNOSIS",
			"celo": "RPC_URL_CELO",
			"moonbeam": "RPC_URL_MOONBEAM",
			"aurora": "RPC_URL_AURORA",
			"cronos": "RPC_URL_CRONOS",
			"mantle": "RPC_URL_MANTLE",
			"polygon-zkevm": "RPC_URL_POLYGON_ZKEVM",
			"polygon_zkevm": "RPC_URL_POLYGON_ZKEVM",
		}
		env_name = mapping.get(key, "RPC_URL_ETHEREUM")
		url = os.getenv(env_name)
		print(f"Getting RPC URL for chain '{key}', env var '{env_name}': {url[:50] if url else 'NOT SET'}...")
		if not url:
			raise HTTPException(status_code=500, detail=f"Missing RPC URL for {key} (env var: {env_name})")
		try:
			w3_clients[key] = Web3(Web3.HTTPProvider(url))
			# Test the connection
			is_connected = w3_clients[key].is_connected()
			print(f"Web3 connection test for {key}: {'SUCCESS' if is_connected else 'FAILED'}")
			if not is_connected:
				raise HTTPException(status_code=500, detail=f"Could not connect to RPC for {key}")
		except Exception as e:
			print(f"Error creating Web3 client for {key}: {e}")
			raise HTTPException(status_code=500, detail=f"Failed to create Web3 client for {key}: {str(e)}")
	return w3_clients[key]


sanctions_checker = local_sanctions_checker

bearer_scheme = HTTPBearer(auto_error=False)

def get_partner_id_from_api_key(authorization: Optional[str] = Header(default=None)) -> str:
	# Support both "Bearer <key>" and raw key in Authorization header,
	# and also FastAPI HTTPBearer if configured later.
	api_key = None
	if authorization:
		api_key = authorization[7:] if authorization.startswith("Bearer ") else authorization
	if not api_key:
		raise HTTPException(status_code=401, detail="Missing API key")
	
	try:
		sb = get_supabase()
		# Try to find by key_hash first (primary storage), then by key (fallback)
		res = sb.table("api_keys").select("partner_id,is_active").eq("key_hash", api_key).limit(1).execute()
		rows = res.data or []
		if not rows:
			# Fallback to key column if key_hash not found
			res = sb.table("api_keys").select("partner_id,is_active").eq("key", api_key).limit(1).execute()
			rows = res.data or []
		
		row = rows[0] if rows else None
		if not row:
			raise HTTPException(status_code=403, detail="API key not found")
		if not row.get("is_active"):
			raise HTTPException(status_code=403, detail="API key is inactive")
		
		partner_id = row.get("partner_id")
		if not partner_id:
			raise HTTPException(status_code=500, detail="API key missing partner_id")
		
		return str(partner_id)
	except HTTPException:
		raise
	except Exception as e:
		print(f"Error validating API key: {e}")
		raise HTTPException(status_code=500, detail="Internal server error during API key validation")


@app.on_event("startup")
async def startup_event() -> None:
	"""Initialize secure systems on startup"""
	try:
		# Initialize wallet risk assessor
		logger.info("Initializing wallet risk assessor...")
		
		# Initialize audit logger
		logger.info("Initializing sanctions audit logger...")
		
		# Initialize confirmation system
		logger.info("Initializing confirmation code system...")
		
		# Clean up expired confirmation codes
		expired_count = confirmation_system.cleanup_expired_codes()
		if expired_count > 0:
			logger.info(f"Cleaned up {expired_count} expired confirmation codes")
		
		# Local sanctions checker loads automatically on first use
		logger.info("Startup complete - secure sanctions management system ready")
		
	except Exception as e:
		logger.error(f"Error during startup: {e}")
		raise


def _apply_policy(sanctioned: bool, score: int, band: str) -> Tuple[bool, Optional[str], bool]:
	"""Return (allowed, status, alert)
	Policy:
	- score==100 or sanctioned/PROHIBITED => block (status='blocked')
	- score==50 => allow with alert (status='alert')
	- score==0 => allow
	- HIGH/CRITICAL (>=80) => block
	- else allow
	"""
	if sanctioned or band == "PROHIBITED" or score >= 100:
		return False, "blocked", False
	if score == 50:
		return True, "alert", True
	if score == 0:
		return True, None, False
	if band in {"HIGH", "CRITICAL"} or score >= 80:
		return False, "blocked", False
	return True, None, False


async def make_decision_with_risk(to_addr: str, features: Optional[List[FeatureHitIn]], 
                                 transaction_context: Optional[Dict] = None,
                                 network_context: Optional[Dict] = None) -> tuple[Decision, List[str], Optional[str]]:
	"""Enhanced risk assessment using the new enterprise risk model.
	Returns (Decision, reasons, status)
	"""
	reasons: List[str] = []
	sanctioned = sanctions_checker.is_sanctioned(to_addr)  # Now synchronous since it's local
	
	if features:
		# Convert features to domain objects
		hits = [f.to_domain() for f in features]
		
		# Use new risk model with context
		score, band, reasons, applied = compute_risk_score(
			hits, 
			sanctioned,
			transaction_context=transaction_context,
			network_context=network_context
		)
		
		try:
			# Enhanced logging with new model
			log_risk_events(to_addr, hits, applied)
			upsert_risk_score(to_addr, score, band, reasons)
		except Exception as e:
			print(f"Warning: Failed to log risk data: {e}")
		
		allowed, status, alert = _apply_policy(sanctioned, score, band)
		if alert:
			reasons = ["ALERT: risk_score==50"] + reasons
		return Decision(allowed=allowed, risk_band=band, risk_score=score, reasons=reasons), reasons, status
	
	# No features provided - calculate base risk from transaction context only
	if transaction_context:
		# Create a minimal feature hit based on transaction context
		from datetime import datetime, timezone
		from .risk_model import FeatureHit
		
		# Calculate base risk from transaction context
		base_risk = 0
		context_reasons = []
		
		if transaction_context.get('is_contract', False):
			base_risk += 15
			context_reasons.append("Contract interaction")
		
		if transaction_context.get('data_size', 0) > 21000:
			base_risk += 10
			context_reasons.append("Complex transaction")
		
		# Create a feature hit for the transaction context
		context_hit = FeatureHit(
			key="TRANSACTION_CONTEXT",
			base=float(base_risk),
			occurred_at=datetime.now(timezone.utc),
			critical=False,
			details=transaction_context
		)
		
		# Use the risk model with this context
		score, band, reasons, applied = compute_risk_score(
			[context_hit], 
			sanctioned,
			transaction_context=transaction_context,
			network_context=network_context
		)
		
		# Add context reasons
		if context_reasons:
			reasons = context_reasons + reasons
		
		allowed, status, alert = _apply_policy(sanctioned, score, band)
		return Decision(allowed=allowed, risk_band=band, risk_score=score, reasons=reasons), reasons, status
	
	# Fallback to DB snapshot
	sb = get_supabase()
	res = sb.table("risk_scores").select("score,band,risk_factors").eq("wallet", (to_addr or "").lower()).limit(1).execute()
	rows = res.data or []
	
	if rows:
		data = rows[0]
		score = int(round(data.get("score") or 0))
		band = data.get("band") or "LOW"
		reasons = data.get("risk_factors") or []
		
		allowed, status, alert = _apply_policy(sanctioned, score, band)
		if alert:
			reasons = ["ALERT: risk_score==50"] + reasons
		return Decision(allowed=allowed, risk_band=band, risk_score=score, reasons=reasons), reasons, status
	
	# No cached score and no context → treat as 0
	allowed, status, _ = _apply_policy(sanctioned, 0, "LOW")
	return Decision(allowed=allowed, risk_band="LOW", risk_score=0, reasons=["No risk factors detected"]), [], status


@app.post("/v1/check", response_model=Decision)
async def v1_check(body: CheckRequest, partner_id: str = Depends(get_partner_id_from_api_key)):
	try:
		# Validate request body: accept 0x-prefixed 40-hex EVM address
		if not body.to or not isinstance(body.to, str):
			raise HTTPException(status_code=400, detail="Missing 'to' address")
		to_norm = body.to.strip()
		if to_norm.lower() == "string":
			raise HTTPException(status_code=400, detail="Invalid 'to' address. Use a real 0x... address (see example in docs).")
		if not (to_norm.startswith("0x") and len(to_norm) == 42):
			raise HTTPException(status_code=400, detail="Invalid 'to' address format. Expected 0x-prefixed EVM address.")
		
		print(f"Processing check request for partner_id: {partner_id}, to: {to_norm}")
		decision, reasons, status = await make_decision_with_risk(to_norm, body.features)
		print(f"Decision: {decision.allowed}, risk_score: {decision.risk_score}, risk_band: {decision.risk_band}")
		
		# Log sanctions check result
		is_sanctioned = sanctions_checker.is_sanctioned(to_norm)
		if is_sanctioned:
			print(f"🚫 SANCTIONED WALLET DETECTED in check: {to_norm}")
		else:
			print(f"✅ Wallet {to_norm} is clean in check")
		
		# log (best-effort)
		try:
			sb = get_supabase()
			sb.table("relay_logs").insert({
				"partner_id": partner_id,
				"chain": body.chain,
				"from_addr": body.from_addr or None,
				"to_addr": body.to,
				"decision": "allowed" if decision.allowed else "blocked",
				"risk_band": decision.risk_band,
				"risk_score": decision.risk_score,
				"reasons": reasons or decision.reasons,
				"created_at": now_iso(),
			}).execute()
		except Exception as e:
			print(f"Warning: Failed to log request: {e}")
		
		return JSONResponse(content=decision.model_dump())
	except HTTPException:
		raise
	except Exception as e:
		print(f"Error in v1_check: {e}")
		raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/v1/relay", response_model=RelayResponse)
async def v1_relay(body: RelayRequest, partner_id: str = Depends(get_partner_id_from_api_key)):
	if not is_hex_string(body.rawTx):
		raise HTTPException(status_code=400, detail="rawTx must be 0x-hex string")

	to = extract_to_address(body.rawTx)
	if to is None:
		raise HTTPException(status_code=400, detail="Missing 'to' in rawTx (contract creation not supported)")

	# Extract transaction context for enhanced risk scoring
	transaction_context = None
	try:
		# Parse raw transaction to get basic info
		raw_bytes = Web3.to_bytes(hexstr=body.rawTx)
		if len(raw_bytes) > 0:
			# Basic transaction analysis
			transaction_context = {
				"data_size": len(raw_bytes),
				"is_contract": len(raw_bytes) > 21000,  # More than basic ETH transfer
				"raw_tx_length": len(body.rawTx)
			}
	except Exception as e:
		print(f"Warning: Could not parse transaction context: {e}")
	
	# Check sanctions first and log clearly
	is_sanctioned = sanctions_checker.is_sanctioned(to)
	if is_sanctioned:
		print(f"🚫 SANCTIONED WALLET DETECTED in relay: {to}")
		print(f"   Transaction will be BLOCKED from broadcasting")
	else:
		print(f"✅ Wallet {to} is clean in relay - proceeding with risk assessment")
	
	decision, reasons, status = await make_decision_with_risk(to, body.features, transaction_context)

	# pre-log
	log_id: Optional[int] = None
	sb = get_supabase()
	try:
		ins = sb.table("relay_logs").insert({
			"partner_id": partner_id,
			"chain": body.chain,
			"from_addr": None,
			"to_addr": to,
			"decision": "allowed" if decision.allowed else "blocked",
			"risk_band": decision.risk_band,
			"risk_score": decision.risk_score,
			"reasons": reasons or decision.reasons,
			"idempotency_key": body.idempotencyKey or None,
			"created_at": now_iso(),
		}).select("id").execute()
		rows = ins.data or []
		if rows:
			log_id = rows[0].get("id")
	except Exception:
		pass

	if not decision.allowed:
		return JSONResponse(status_code=403, content={
			"allowed": False,
			"risk_band": decision.risk_band,
			"risk_score": decision.risk_score,
			"reasons": reasons or decision.reasons,
			"status": "blocked",
		})

	# broadcast (allowed or alert)
	try:
		print(f"Attempting to broadcast transaction for chain: {body.chain}")
		w3 = get_w3(body.chain)
		print(f"Web3 instance created successfully")
		
		raw_bytes = Web3.to_bytes(hexstr=body.rawTx)
		print(f"Raw transaction converted to bytes, length: {len(raw_bytes)}")
		
		# Try to decode the transaction first to validate it
		try:
			from eth_account._utils.legacy_transactions import decode_transaction
			decoded_tx = decode_transaction(body.rawTx)
			print(f"Transaction decoded successfully, from: {decoded_tx['from']}, to: {decoded_tx['to']}, nonce: {decoded_tx['nonce']}")
		except Exception as decode_error:
			print(f"Warning: Could not decode transaction: {decode_error}")
		
		tx_hash = w3.eth.send_raw_transaction(raw_bytes)
		print(f"Transaction broadcast successful, hash: {tx_hash}")
		
		tx_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else Web3.to_hex(tx_hash)
		if log_id is not None:
			try:
				sb.table("relay_logs").update({"tx_hash": tx_hex}).eq("id", log_id).execute()
			except Exception as log_error:
				print(f"Warning: Failed to update log with tx_hash: {log_error}")
		
		return JSONResponse(content={
			"allowed": True,
			"risk_band": decision.risk_band,
			"risk_score": decision.risk_score,
			"txHash": tx_hex,
			"reasons": reasons or decision.reasons,
			"status": status,
		})
	except Exception as e:
		print(f"Error broadcasting transaction: {e}")
		print(f"Error type: {type(e)}")
		
		# Determine specific error type and provide helpful message
		error_detail = str(e)
		if "insufficient funds" in error_detail.lower():
			status_code = 400
			detail = "Insufficient funds for transaction"
		elif "nonce too low" in error_detail.lower():
			status_code = 400
			detail = "Transaction nonce too low (transaction already processed)"
		elif "already known" in error_detail.lower():
			status_code = 400
			detail = "Transaction already known to network"
		elif "gas price too low" in error_detail.lower():
			status_code = 400
			detail = "Gas price too low for current network conditions"
		elif "chain not found" in error_detail.lower():
			status_code = 400
			detail = f"Chain '{body.chain}' not supported or RPC not configured"
		else:
			status_code = 500
			detail = f"Transaction broadcast failed: {error_detail}"
		
		raise HTTPException(status_code=status_code, detail=detail)


@app.get("/v1/sanctions/list")
async def get_sanctions_list(partner_id: str = Depends(get_partner_id_from_api_key)):
	"""Get the current list of sanctioned wallet addresses"""
	try:
		# Get the current sanctions list
		sanctioned_count = sanctions_checker.get_sanctioned_count()
		
		# Read the JSON file to get the full list
		import json
		from pathlib import Path
		
		file_path = Path(__file__).parent.parent / "sanctioned_wallets.json"
		if file_path.exists():
			with open(file_path, 'r', encoding='utf-8') as f:
				data = json.load(f)
			
			return {
				"success": True,
				"total_count": sanctioned_count,
				"addresses": data.get("sanctioned_addresses", []),
				"last_updated": data.get("last_updated", ""),
				"description": data.get("description", "")
			}
		else:
			return {
				"success": False,
				"message": "Sanctions file not found",
				"total_count": 0,
				"addresses": [],
				"last_updated": "",
				"description": ""
			}
			
	except Exception as e:
		print(f"Error getting sanctions list: {e}")
		raise HTTPException(status_code=500, detail=f"Failed to retrieve sanctions list: {str(e)}")


# Updated sanctions manage: path param address; body optional reason; only 'add'
@app.post("/v1/sanctions/manage/{address}", response_model=SanctionsResponse)
async def manage_sanctions(
	address: str,
	request: SanctionsManageRequest,
	partner_id: str = Depends(get_partner_id_from_api_key)
):
	"""Add a wallet to sanctions list after Etherscan+Bitquery risk validation."""
	try:
		addr = (address or "").lower().strip()
		logger.info(f"Sanctions management (add) request for {addr} by {partner_id}")
		# Validate address format
		if not wallet_risk_assessor.is_valid_address(addr):
			raise HTTPException(status_code=400, detail="Invalid address format")
		# Already sanctioned? quick exit
		if sanctions_checker.is_sanctioned(addr):
			return JSONResponse(status_code=409, content={
				"success": False,
				"message": f"Address {addr} is already in sanctions list",
				"address": addr,
				"action": "add",
				"total_count": sanctions_checker.get_sanctioned_count()
			})
		# Risk assessment (ethereum by default)
		risk_profile = await wallet_risk_assessor.assess_wallet_risk(addr, "ethereum")
		if risk_profile.risk_score < 70:
			raise HTTPException(status_code=400, detail=f"Insufficient risk (score: {risk_profile.risk_score}) to sanction")
		if risk_profile.confidence < 0.6:
			raise HTTPException(status_code=400, detail=f"Insufficient data confidence ({risk_profile.confidence:.2f}) to sanction")
		# Add to sanctions
		success = sanctions_checker.add_sanctioned_address(addr)
		if not success:
			raise HTTPException(status_code=500, detail="Failed to add address to sanctions list")
		# Audit
		await audit_logger.log_sanctions_action(
			partner_id=partner_id,
			action="ADD",
			address=addr,
			risk_score=risk_profile.risk_score,
			risk_factors=risk_profile.risk_factors,
			data_sources=risk_profile.data_sources,
			reason=getattr(request, "reason", None)
		)
		return SanctionsResponse(
			success=True,
			message=f"Address {addr} added to sanctions list",
			address=addr,
			action="add",
			risk_profile={
				"risk_score": risk_profile.risk_score,
				"confidence": risk_profile.confidence,
				"risk_factors": risk_profile.risk_factors,
				"data_sources": risk_profile.data_sources,
				"transaction_count": risk_profile.transaction_count,
				"total_volume": risk_profile.total_volume,
				"last_activity": risk_profile.last_activity,
				"suspicious_patterns": risk_profile.suspicious_patterns
			},
			total_count=sanctions_checker.get_sanctioned_count()
		)
	except HTTPException:
		raise
	except Exception as e:
		logger.error(f"Sanctions management error: {e}")
		raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/v1/sanctions/check/{address}")
async def check_sanctions_status(address: str, partner_id: str = Depends(get_partner_id_from_api_key)):
	"""Check if a specific wallet address is sanctioned"""
	try:
		# Validate address format
		if not address.startswith("0x") or len(address) != 42:
			raise HTTPException(status_code=400, detail="Invalid wallet address format. Must be 0x-prefixed 42-character hex string.")
		
		# Check sanctions status
		is_sanctioned = sanctions_checker.is_sanctioned(address)
		
		return {
			"address": address,
			"is_sanctioned": is_sanctioned,
			"status": "SANCTIONED" if is_sanctioned else "CLEAN",
			"message": f"Address {address} is {'SANCTIONED' if is_sanctioned else 'CLEAN'}",
			"checked_at": now_iso()
		}
		
	except HTTPException:
		raise
	except Exception as e:
		print(f"Error checking sanctions status: {e}")
		raise HTTPException(status_code=500, detail=f"Failed to check sanctions status: {str(e)}")


## (Removed endpoint POST /v1/wallet/assess)


## (Removed endpoint GET /v1/sanctions/stats)


@app.get("/v1/audit/logs")
async def get_audit_logs(
    partner_id: str = Depends(get_partner_id_from_api_key),
    action: Optional[str] = None,
    address: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
):
    """Get audit logs for sanctions operations"""
    
    try:
        logs = await audit_logger.get_audit_logs(
            partner_id=partner_id,
            action=action,
            address=address,
            start_date=start_date,
            end_date=end_date,
            limit=limit
        )
        
        return {
            "success": True,
            "total_logs": len(logs),
            "logs": logs,
            "filters": {
                "partner_id": partner_id,
                "action": action,
                "address": address,
                "start_date": start_date,
                "end_date": end_date,
                "limit": limit
            }
        }
        
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit logs")


@app.get("/v1/audit/summary")
async def get_audit_summary(partner_id: str = Depends(get_partner_id_from_api_key)):
    """Get summary statistics of audit logs"""
    
    try:
        summary = await audit_logger.get_audit_summary(partner_id=partner_id)
        
        return {
            "success": True,
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"Error generating audit summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate audit summary")


## (Removed endpoint POST /v1/confirmation/generate)


if __name__ == "__main__":
	import uvicorn
	uvicorn.run(app, host="0.0.0.0", port=8000)

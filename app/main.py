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


class BitqueryTransfersRequest(BaseModel):
	network: str = Field(default="eth", description="Bitquery network, e.g., eth")
	tokenAddresses: Optional[List[str]] = Field(default=None, description="Filter by token contract addresses")
	limit: int = Field(default=50, ge=1, le=200)

class BitqueryTransferRow(BaseModel):
	token_symbol: str
	amount: float
	sender: str
	receiver: str
	timestamp: str

class EtherscanWalletRequest(BaseModel):
	address: str

class EtherscanTxRow(BaseModel):
	hash: str
	timeStamp: str
	value_eth: float
	from_addr: str
	to_addr: Optional[str]
	isError: bool

class EtherscanWalletResponse(BaseModel):
	address: str
	tx_count: int
	first_tx_time: Optional[str]
	failed_ratio: float
	risk_rating: int
	txs: List[EtherscanTxRow]


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


@app.post("/v1/sanctions/manage", response_model=SanctionsResponse)
async def manage_sanctions(
    request: SanctionsManageRequest,
    partner_id: str = Depends(get_partner_id_from_api_key)
):
    """Secure sanctions management with risk validation and audit logging"""
    
    try:
        address = request.address.lower()
        action = request.action.lower()
        
        logger.info(f"Sanctions management request: {action} for {address} by {partner_id}")
        
        # Validate address format using the risk assessor
        if not wallet_risk_assessor.is_valid_address(address):
            raise HTTPException(status_code=400, detail="Invalid address format")
        
        # Check if address is currently sanctioned
        is_currently_sanctioned = sanctions_checker.is_sanctioned(address)
        
        if action == "add":
            if is_currently_sanctioned:
                return SanctionsResponse(
                    success=False,
                    message=f"Address {address} is already in sanctions list",
                    address=address,
                    action=action,
                    total_count=sanctions_checker.get_sanctioned_count()
                )
            
            # CRITICAL: Validate wallet before adding to sanctions
            logger.info(f"Starting risk assessment for {address}")
            risk_profile = await wallet_risk_assessor.assess_wallet_risk(address, request.chain)
            
            # Security checks
            if risk_profile.risk_score < 70:  # Require high risk for sanctions
                raise HTTPException(
                    status_code=400, 
                    detail=f"Address {address} has insufficient risk (score: {risk_profile.risk_score}) to be sanctioned. Minimum required: 70"
                )
            
            if risk_profile.confidence < 0.6:  # Require good data quality
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient data confidence ({risk_profile.confidence:.2f}) for {address}. Cannot safely sanction."
                )
            
            # Check if admin approval is required
            if confirmation_system.require_admin_approval(partner_id, address, risk_profile.risk_score):
                raise HTTPException(
                    status_code=403,
                    detail="Admin approval required for this sanctions operation. Contact support."
                )
            
            # Log the risk assessment
            logger.info(f"Risk assessment for {address}: Score={risk_profile.risk_score}, Confidence={risk_profile.confidence}")
            
            # Add to sanctions with risk metadata
            success = sanctions_checker.add_sanctioned_address(address)
            
            if success:
                # Log the action for audit
                await audit_logger.log_sanctions_action(
                    partner_id=partner_id,
                    action="ADD",
                    address=address,
                    risk_score=risk_profile.risk_score,
                    risk_factors=risk_profile.risk_factors,
                    data_sources=risk_profile.data_sources,
                    reason=request.reason
                )
                
                return SanctionsResponse(
                    success=True,
                    message=f"Address {address} added to sanctions list",
                    address=address,
                    action=action,
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
            else:
                raise HTTPException(status_code=500, detail="Failed to add address to sanctions list")
                
        elif action == "remove":
            if not is_currently_sanctioned:
                return SanctionsResponse(
                    success=False,
                    message=f"Address {address} is not in sanctions list",
                    address=address,
                    action=action,
                    total_count=sanctions_checker.get_sanctioned_count()
                )
            
            # CRITICAL: Additional validation before removal
            current_risk = await wallet_risk_assessor.assess_wallet_risk(address, request.chain)
            
            # Only allow removal if risk has significantly decreased
            if current_risk.risk_score > 30:  # Still risky
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot remove {address} - still has high risk (score: {current_risk.risk_score})"
                )
            
            # Require additional confirmation for removal
            if not request.confirmation_code:
                raise HTTPException(
                    status_code=400,
                    detail="Removal requires confirmation code for security"
                )
            
            # Verify confirmation code
            is_valid, message = confirmation_system.verify_confirmation_code(
                request.confirmation_code, partner_id, address, action
            )
            
            if not is_valid:
                raise HTTPException(status_code=400, detail=f"Invalid confirmation code: {message}")
            
            success = sanctions_checker.remove_sanctioned_address(address)
            
            if success:
                # Log the removal action
                await audit_logger.log_sanctions_action(
                    partner_id=partner_id,
                    action="REMOVE",
                    address=address,
                    risk_score=current_risk.risk_score,
                    risk_factors=current_risk.risk_factors,
                    data_sources=current_risk.data_sources,
                    reason=request.reason
                )
                
                return SanctionsResponse(
                    success=True,
                    message=f"Address {address} removed from sanctions list",
                    address=address,
                    action=action,
                    total_count=sanctions_checker.get_sanctioned_count()
                )
            else:
                raise HTTPException(status_code=500, detail="Failed to remove address from sanctions list")
                
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


@app.post("/v1/wallet/assess", response_model=WalletRiskAssessmentResponse)
async def assess_wallet_risk(
    request: WalletRiskAssessmentRequest,
    partner_id: str = Depends(get_partner_id_from_api_key)
):
    """Assess wallet risk without adding to sanctions"""
    
    try:
        address = request.address.lower()
        
        logger.info(f"Wallet risk assessment request for {address} by {partner_id}")
        
        # Validate address format
        if not wallet_risk_assessor.is_valid_address(address):
            raise HTTPException(status_code=400, detail="Invalid address format")
        
        # Perform comprehensive risk assessment
        risk_profile = await wallet_risk_assessor.assess_wallet_risk(address, request.chain)
        
        # Determine risk band
        if risk_profile.risk_score >= 90:
            risk_band = "CRITICAL"
        elif risk_profile.risk_score >= 80:
            risk_band = "HIGH"
        elif risk_profile.risk_score >= 60:
            risk_band = "MEDIUM"
        elif risk_profile.risk_score >= 40:
            risk_band = "ELEVATED"
        else:
            risk_band = "LOW"
        
        # Generate recommendation
        if risk_profile.risk_score >= 80:
            recommendation = "BLOCK - High risk wallet detected"
        elif risk_profile.risk_score >= 60:
            recommendation = "MONITOR - Elevated risk, consider additional screening"
        elif risk_profile.risk_score >= 40:
            recommendation = "REVIEW - Moderate risk, standard screening recommended"
        else:
            recommendation = "ALLOW - Low risk wallet"
        
        # Log the assessment for audit
        await audit_logger.log_sanctions_action(
            partner_id=partner_id,
            action="ASSESS",
            address=address,
            risk_score=risk_profile.risk_score,
            risk_factors=risk_profile.risk_factors,
            data_sources=risk_profile.data_sources,
            reason="Risk assessment request"
        )
        
        return WalletRiskAssessmentResponse(
            address=address,
            risk_score=risk_profile.risk_score,
            risk_band=risk_band,
            risk_factors=risk_profile.risk_factors,
            confidence=risk_profile.confidence,
            data_sources=risk_profile.data_sources,
            transaction_count=risk_profile.transaction_count,
            total_volume=risk_profile.total_volume,
            last_activity=risk_profile.last_activity,
            suspicious_patterns=risk_profile.suspicious_patterns,
            assessment_timestamp=risk_profile.assessment_timestamp,
            recommendation=recommendation
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Wallet risk assessment error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/v1/sanctions/stats")
async def get_sanctions_stats(partner_id: str = Depends(get_partner_id_from_api_key)):
	"""Get statistics about the sanctions list"""
	try:
		total_count = sanctions_checker.get_sanctioned_count()
		
		# Read the JSON file to get additional stats
		import json
		from pathlib import Path
		
		file_path = Path(__file__).parent.parent / "sanctioned_wallets.json"
		if file_path.exists():
			with open(file_path, 'r', encoding='utf-8') as f:
				data = json.load(f)
			
			last_updated = data.get("last_updated", "")
			description = data.get("description", "")
		else:
			last_updated = ""
			description = ""
		
		return {
			"total_sanctioned_addresses": total_count,
			"last_updated": last_updated,
			"description": description,
			"file_path": str(file_path),
			"file_exists": file_path.exists(),
			"checked_at": now_iso()
		}
		
	except Exception as e:
		print(f"Error getting sanctions stats: {e}")
		raise HTTPException(status_code=500, detail=f"Failed to retrieve sanctions stats: {str(e)}")


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


@app.post("/v1/confirmation/generate")
async def generate_confirmation_code(
    address: str,
    action: str,
    partner_id: str = Depends(get_partner_id_from_api_key)
):
    """Generate a confirmation code for sanctions removal"""
    
    try:
        if action not in ["remove"]:
            raise HTTPException(status_code=400, detail="Confirmation codes only available for removal actions")
        
        # Validate address format
        if not wallet_risk_assessor.is_valid_address(address):
            raise HTTPException(status_code=400, detail="Invalid address format")
        
        # Generate confirmation code
        confirmation_code = confirmation_system.generate_confirmation_code(partner_id, address, action)
        
        return {
            "success": True,
            "confirmation_code": confirmation_code,
            "address": address,
            "action": action,
            "expires_in": "1 hour",
            "message": "Use this confirmation code when removing the address from sanctions"
        }
        
    except Exception as e:
        logger.error(f"Error generating confirmation code: {e}")
        if "Rate limit exceeded" in str(e):
            raise HTTPException(status_code=429, detail="Too many confirmation code requests. Please wait before requesting another.")
        raise HTTPException(status_code=500, detail="Failed to generate confirmation code")

# Bitquery streaming transfers endpoint
@app.post("/v1/bitquery/transfers", response_model=List[BitqueryTransferRow])
async def bitquery_transfers(body: BitqueryTransfersRequest, partner_id: str = Depends(get_partner_id_from_api_key)):
	"""Proxy Bitquery streaming GraphQL to fetch recent token transfers (e.g., USDC/USDT)."""
	access_token = get_secret("BITQUERY_TOKEN", env_var="BITQUERY_TOKEN")
	if not access_token:
		raise HTTPException(status_code=500, detail="Missing Bitquery access token")
	try:
		headers = {
			"Content-Type": "application/json",
			"Authorization": f"Bearer {access_token}"
		}
		# Use provided tokens or default to USDC/USDT on Ethereum
		tokens = body.tokenAddresses or [
			"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
			"0xdac17f958d2ee523a2206206994597c13d831ec7"   # USDT
		]
		query = {
			"query": """
			{ EVM(dataset: realtime, network: eth) {
			  Transfers(
			    where: { Transfer: { Currency: { SmartContract: { in: TOKEN_LIST } } } }
			    limit: {count: LIMIT}
			    orderBy: {descending: Block_Time}
			  ) {
			    Block { Time }
			    Transfer {
			      Amount
			      Currency { Name Symbol }
			      Sender
			      Receiver
			    }
			  }
			} }
			""".replace("TOKEN_LIST", str(tokens)).replace("LIMIT", str(body.limit))
		}
		resp = requests.post("https://streaming.bitquery.io/graphql", json=query, headers=headers, timeout=20)
		if resp.status_code != 200:
			raise HTTPException(status_code=resp.status_code, detail=f"Bitquery error: {resp.text[:200]}")
		data = resp.json()
		rows = data.get("data", {}).get("EVM", {}).get("Transfers", [])
		out: List[BitqueryTransferRow] = []
		for r in rows:
			blk = r.get("Block", {})
			tr = r.get("Transfer", {})
			cur = (tr.get("Currency") or {})
			out.append(BitqueryTransferRow(
				token_symbol=str(cur.get("Symbol") or cur.get("Name") or ""),
				amount=float(tr.get("Amount") or 0),
				sender=str(tr.get("Sender") or ""),
				receiver=str(tr.get("Receiver") or ""),
				timestamp=str(blk.get("Time") or "")
			))
		return out
	except HTTPException:
		raise
	except Exception as e:
		logger.error(f"Bitquery transfers error: {e}")
		raise HTTPException(status_code=500, detail="Failed to fetch transfers")


def _format_etherscan_tx(tx: Dict[str, Any]) -> EtherscanTxRow:
	value_eth = 0.0
	try:
		value_eth = float(tx.get("value", "0")) / 1e18
	except Exception:
		value_eth = 0.0
	# human time
	try:
		ts = int(tx.get("timeStamp", "0"))
		iso = datetime.fromtimestamp(ts, tz.utc).isoformat()
	except Exception:
		iso = ""
	return EtherscanTxRow(
		hash=str(tx.get("hash")),
		timeStamp=iso,
		value_eth=value_eth,
		from_addr=str(tx.get("from")),
		to_addr=str(tx.get("to")) if tx.get("to") else None,
		isError=str(tx.get("isError", "0")) == "1",
	)


def _basic_wallet_risk(txs: List[EtherscanTxRow]) -> Tuple[int, Optional[str], float]:
	"""Compute a simple 0-100 risk rating based on age, activity, and failures."""
	if not txs:
		return 20, None, 0.0
	# Age
	first_time = txs[-1].timeStamp or txs[-1].timeStamp
	first_ts = None
	try:
		first_ts = datetime.fromisoformat(first_time.replace("Z", "+00:00")) if first_time else None
	except Exception:
		first_ts = None
	now = datetime.now(tz.utc)
	age_days = 0
	if first_ts:
		age_days = max(0, (now - first_ts).days)
	# Fail ratio
	fails = sum(1 for t in txs if t.isError)
	ratio = (fails / len(txs)) if txs else 0.0
	# Tx count
	count = len(txs)
	# Scoring (higher = riskier)
	score = 0
	if age_days < 7:
		score += 20
	elif age_days < 30:
		score += 10
	if count > 1000:
		score += 20
	elif count > 200:
		score += 10
	if ratio > 0.2:
		score += 20
	elif ratio > 0.05:
		score += 10
	return min(100, score), (first_ts.isoformat() if first_ts else None), ratio


@app.post("/v1/wallet/etherscan_txs", response_model=EtherscanWalletResponse)
async def etherscan_wallet_txs(body: EtherscanWalletRequest, partner_id: str = Depends(get_partner_id_from_api_key)):
	"""Fetch wallet transactions from Etherscan and return normalized fields + basic risk rating."""
	address = body.address.strip()
	if not wallet_risk_assessor.is_valid_address(address):
		raise HTTPException(status_code=400, detail="Invalid address format")
	api_key = get_secret("ETHERSCAN_API_KEY", env_var="ETHERSCAN_API_KEY")
	if not api_key:
		raise HTTPException(status_code=500, detail="Missing ETHERSCAN_API_KEY")
	try:
		params = {
			"module": "account",
			"action": "txlist",
			"address": address,
			"startblock": 0,
			"endblock": 99999999,
			"sort": "desc",
			"apikey": api_key,
		}
		resp = requests.get("https://api.etherscan.io/api", params=params, timeout=20)
		if resp.status_code != 200:
			raise HTTPException(status_code=resp.status_code, detail=f"Etherscan error: {resp.text[:200]}")
		payload = resp.json()
		if str(payload.get("status")) != "1":
			# No txs or error
			txs_raw = payload.get("result", [])
		else:
			txs_raw = payload.get("result", [])
		txs = [_format_etherscan_tx(tx) for tx in txs_raw]
		risk, first_time, fail_ratio = _basic_wallet_risk(txs)
		return EtherscanWalletResponse(
			address=address,
			tx_count=len(txs),
			first_tx_time=first_time,
			failed_ratio=round(fail_ratio, 4),
			risk_rating=risk,
			txs=txs,
		)
	except HTTPException:
		raise
	except Exception as e:
		logger.error(f"Etherscan wallet txs error: {e}")
		raise HTTPException(status_code=500, detail="Failed to fetch wallet transactions")


if __name__ == "__main__":
	import uvicorn
	uvicorn.run(app, host="0.0.0.0", port=8000)

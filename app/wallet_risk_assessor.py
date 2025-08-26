import requests
import time
import os
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger(__name__)

try:
    # Lazy import to avoid circulars in certain contexts
    from .secrets import get_secret
except Exception:
    # Fallback shim
    def get_secret(name: str, env_var: Optional[str] = None) -> Optional[str]:
        return os.getenv(env_var or name)

@dataclass
class WalletRiskProfile:
    address: str
    risk_score: int
    risk_factors: List[str]
    confidence: float
    data_sources: List[str]
    last_activity: Optional[str]
    transaction_count: Optional[int]
    total_volume: Optional[str]
    suspicious_patterns: List[str]
    assessment_timestamp: str
    balance_eth: Optional[float] = None

class WalletRiskAssessor:
    def __init__(self):
        # Load from env first, then Supabase secrets fallback
        self.etherscan_api_key = get_secret("ETHERSCAN_API_KEY", env_var="ETHERSCAN_API_KEY")
        # Bitquery uses Access Token (Bearer), not API key
        self.bitquery_token = get_secret("BITQUERY_TOKEN", env_var="BITQUERY_TOKEN")
        self.alchemy_api_key = get_secret("ALCHEMY_API_KEY", env_var="ALCHEMY_API_KEY")
        self.moralis_api_key = get_secret("MORALIS_API_KEY", env_var="MORALIS_API_KEY")
        self.covalent_api_key = get_secret("COVALENT_API_KEY", env_var="COVALENT_API_KEY")
        self.tatum_api_key = get_secret("TATUM_API_KEY", env_var="TATUM_API_KEY")
        
        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 1.0  # 1 second between requests
        
    async def assess_wallet_risk(self, address: str, chain: str = "ethereum") -> WalletRiskProfile:
        """Comprehensive risk assessment using multiple data sources"""
        
        risk_factors: List[str] = []
        data_sources: List[str] = []
        confidence = 0.0
        risk_score = 0
        transaction_count = 0
        total_volume = "0"
        last_activity: Optional[str] = None
        suspicious_patterns: List[str] = []
        balance_eth: Optional[float] = None
        
        logger.info(f"Starting risk assessment for {address} on {chain}")
        
        # 1. Etherscan Analysis (Primary source)
        if self.etherscan_api_key:
            analyze = getattr(self, "_analyze_etherscan", None)
            if analyze is None:
                analyze = self.__analyze_etherscan_fallback
            etherscan_data = await analyze(address, chain)
            if etherscan_data:
                risk_factors.extend(etherscan_data["risk_factors"])
                risk_score += etherscan_data["risk_score"]
                data_sources.append("etherscan")
                confidence += 0.4
                transaction_count = etherscan_data.get("transaction_count", 0)
                total_volume = etherscan_data.get("total_volume", "0")
                last_activity = etherscan_data.get("last_activity")
                suspicious_patterns.extend(etherscan_data.get("suspicious_patterns", []))
                
            # Also fetch balance from Etherscan
            bal = self._etherscan_balance(address)
            if bal is not None:
                balance_eth = bal
                if balance_eth > 1000:  # > 1000 ETH
                    risk_factors.append("Very high balance")
                    risk_score += 10
        
        # 2. Bitquery Analysis (Cross-chain data via Bearer token)
        if self.bitquery_token:
            bitquery_data = await self._analyze_bitquery(address, chain)
            if bitquery_data:
                risk_factors.extend(bitquery_data["risk_factors"])
                risk_score += bitquery_data["risk_score"]
                data_sources.append("bitquery")
                confidence += 0.3
                
        # 3. Free Alternative: Blockchain.com API
        blockchain_data = await self._analyze_blockchain_com(address, chain)
        if blockchain_data:
            risk_factors.extend(blockchain_data["risk_factors"])
            risk_score += blockchain_data["risk_score"]
            data_sources.append("blockchain.com")
            confidence += 0.2
            
        # 4. Free Alternative: Covalent API
        if self.covalent_api_key:
            covalent_data = await self._analyze_covalent(address, chain)
            if covalent_data:
                risk_factors.extend(covalent_data["risk_factors"])
                risk_score += covalent_data["risk_score"]
                data_sources.append("covalent")
                confidence += 0.1
                
        # 5. Free Alternative: Tatum API
        if self.tatum_api_key:
            tatum_data = await self._analyze_tatum(address, chain)
            if tatum_data:
                risk_factors.extend(tatum_data["risk_factors"])
                risk_score += tatum_data["risk_score"]
                data_sources.append("tatum")
                confidence += 0.1
        
        # Remove duplicate risk factors
        risk_factors = list(set(risk_factors))
        suspicious_patterns = list(set(suspicious_patterns))
        
        # Normalize risk score (0-100)
        risk_score = min(100, max(0, risk_score))
        
        # Ensure minimum confidence if we have some data
        if data_sources:
            confidence = max(confidence, 0.1)
        
        logger.info(f"Risk assessment complete for {address}: Score={risk_score}, Confidence={confidence:.2f}")
        
        return WalletRiskProfile(
            address=address,
            risk_score=risk_score,
            risk_factors=risk_factors,
            confidence=confidence,
            data_sources=data_sources,
            last_activity=last_activity,
            transaction_count=transaction_count,
            total_volume=total_volume,
            suspicious_patterns=suspicious_patterns,
            assessment_timestamp=datetime.utcnow().isoformat(),
            balance_eth=balance_eth
        )
    
    def _rate_limit(self, source: str):
        """Simple rate limiting to avoid API abuse"""
        current_time = time.time()
        if source in self.last_request_time:
            time_since_last = current_time - self.last_request_time[source]
            if time_since_last < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last)
        self.last_request_time[source] = time.time()
    
    def _etherscan_balance(self, address: str) -> Optional[float]:
        """Fetch current balance via Etherscan (in ETH)."""
        try:
            if not self.etherscan_api_key:
                return None
            url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": self.etherscan_api_key
            }
            resp = requests.get(url, params=params, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                wei = data.get("result")
                if wei is not None:
                    return float(wei) / 1e18
        except Exception as e:
            logger.warning(f"Etherscan balance fetch failed: {e}")
        return None

    async def __analyze_etherscan_fallback(self, address: str, chain: str) -> Optional[Dict]:
        """Fallback Etherscan analyzer used if _analyze_etherscan is not bound (safety)."""
        try:
            self._rate_limit("etherscan")
            url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "desc",
                "apikey": self.etherscan_api_key
            }
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    transactions = data.get("result", [])
                    return self._process_etherscan_data(transactions, address)
        except Exception as e:
            logger.error(f"Fallback Etherscan analysis failed: {e}")
        return None

    async def _analyze_etherscan(self, address: str, chain: str) -> Optional[Dict]:
        """Analyze wallet using Etherscan API"""
        try:
            self._rate_limit("etherscan")
            
            url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "desc",
                "apikey": self.etherscan_api_key
            }
            
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    transactions = data.get("result", [])
                    return self._process_etherscan_data(transactions, address)
                elif data.get("status") == "0":
                    logger.warning(f"Etherscan API status=0: {data.get('message', 'Unknown error')}")
            else:
                logger.warning(f"Etherscan HTTP {response.status_code}: {response.text[:200]}")
        except Exception as e:
            logger.error(f"Etherscan analysis failed: {e}")
        return None
    
    def _bitquery_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.bitquery_token}"
        }
    
    async def _analyze_bitquery(self, address: str, chain: str) -> Optional[Dict]:
        """Analyze wallet using Bitquery (Bearer access token). Uses the standard GraphQL endpoint for summary."""
        if not self.bitquery_token:
            return None
        try:
            self._rate_limit("bitquery")
            
            query = (
                """
                query ($address: String!) {
                  ethereum(network: ethereum) {
                    address(address: {is: $address}) {
                      address
                      annotation
                    }
                    transfers: transfers(
                      options: {desc: "block.timestamp.time", limit: 100}
                      amount: {gt: 0}
                      receiver: {is: $address}
                    ) {
                      block { timestamp { time } }
                      amount
                      currency { symbol name address }
                      sender: sender_address
                      receiver: receiver_address
                    }
                  }
                }
                """
            )
            variables = {"address": address}
            resp = requests.post(
                "https://graphql.bitquery.io",
                json={"query": query, "variables": variables},
                headers=self._bitquery_headers(),
                timeout=20
            )
            if resp.status_code == 200:
                data = resp.json()
                return self._process_bitquery_data(data, address)
            else:
                logger.warning(f"Bitquery HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.error(f"Bitquery analysis failed: {e}")
        return None
    
    async def _analyze_blockchain_com(self, address: str, chain: str) -> Optional[Dict]:
        """Free alternative: Blockchain.com API"""
        try:
            self._rate_limit("blockchain.com")
            if chain == "ethereum":
                url = f"https://blockchain.info/rawaddr/{address}"
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    return self._process_blockchain_com_data(data, address)
        except Exception as e:
            logger.error(f"Blockchain.com analysis failed: {e}")
        return None
    
    async def _analyze_covalent(self, address: str, chain: str) -> Optional[Dict]:
        """Free alternative: Covalent API"""
        try:
            self._rate_limit("covalent")
            chain_id = self._get_covalent_chain_id(chain)
            if chain_id and self.covalent_api_key:
                url = f"https://api.covalenthq.com/v1/{chain_id}/address/{address}/transactions_v3/"
                headers = {"Authorization": f"Bearer {self.covalent_api_key}"}
                response = requests.get(url, headers=headers, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    return self._process_covalent_data(data, address)
        except Exception as e:
            logger.error(f"Covalent analysis failed: {e}")
        return None
    
    async def _analyze_tatum(self, address: str, chain: str) -> Optional[Dict]:
        """Free alternative: Tatum API"""
        try:
            self._rate_limit("tatum")
            if chain == "ethereum" and self.tatum_api_key:
                url = f"https://api.tatum.io/v3/ethereum/account/{address}/transaction"
                headers = {"x-api-key": self.tatum_api_key}
                response = requests.get(url, headers=headers, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    return self._process_tatum_data(data, address)
        except Exception as e:
            logger.error(f"Tatum analysis failed: {e}")
        return None
    
    def _process_etherscan_data(self, transactions: List, address: str) -> Dict:
        """Process Etherscan transaction data for risk factors"""
        risk_factors: List[str] = []
        risk_score = 0
        suspicious_patterns: List[str] = []
        
        if not transactions:
            return {
                "risk_factors": ["No transaction history"],
                "risk_score": 10,
                "transaction_count": 0,
                "total_volume": "0",
                "last_activity": None,
                "suspicious_patterns": []
            }
        
        # Analyze transaction patterns
        tx_count = len(transactions)
        total_value = sum(float(tx.get("value", 0)) for tx in transactions)
        
        # Get last activity
        last_activity = None
        if transactions:
            last_tx = transactions[0]
            try:
                last_activity = datetime.fromtimestamp(int(last_tx.get("timeStamp", 0))).isoformat()
            except Exception:
                last_activity = None
        
        # Risk factors based on patterns
        if tx_count > 1000:
            risk_factors.append("High transaction volume")
            risk_score += 15
            
        if total_value > 1000000000000000000000:  # > 1000 ETH
            risk_factors.append("High value transactions")
            risk_score += 20
            
        # Check for suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(transactions)
        risk_factors.extend(suspicious_patterns)
        risk_score += len(suspicious_patterns) * 5
        
        return {
            "risk_factors": risk_factors,
            "risk_score": risk_score,
            "transaction_count": tx_count,
            "total_volume": str(total_value),
            "last_activity": last_activity,
            "suspicious_patterns": suspicious_patterns
        }
    
    def _process_bitquery_data(self, data: Dict, address: str) -> Dict:
        """Process Bitquery data for risk factors (lightweight)"""
        risk_factors: List[str] = []
        risk_score = 0
        try:
            transfers = (
                data.get("data", {})
                    .get("ethereum", {})
                    .get("transfers", [])
            )
            if len(transfers) > 200:
                risk_factors.append("Very high incoming transfer count")
                risk_score += 10
        except Exception as e:
            logger.error(f"Error processing Bitquery data: {e}")
        return {"risk_factors": risk_factors, "risk_score": risk_score}
    
    def _process_blockchain_com_data(self, data: Dict, address: str) -> Dict:
        """Process Blockchain.com data for risk factors"""
        risk_factors: List[str] = []
        risk_score = 0
        try:
            tx_count = data.get("n_tx", 0)
            total_received = data.get("total_received", 0)
            if tx_count > 1000:
                risk_factors.append("High transaction volume")
                risk_score += 15
            if total_received > 1000000000000000000000:
                risk_factors.append("High incoming value")
                risk_score += 15
        except Exception as e:
            logger.error(f"Error processing Blockchain.com data: {e}")
        return {"risk_factors": risk_factors, "risk_score": risk_score}
    
    def _process_covalent_data(self, data: Dict, address: str) -> Dict:
        risk_factors: List[str] = []
        risk_score = 0
        try:
            items = data.get("data", {}).get("items", [])
            if len(items) > 100:
                risk_factors.append("High transaction count")
                risk_score += 10
        except Exception as e:
            logger.error(f"Error processing Covalent data: {e}")
        return {"risk_factors": risk_factors, "risk_score": risk_score}
    
    def _process_tatum_data(self, data: Dict, address: str) -> Dict:
        risk_factors: List[str] = []
        risk_score = 0
        try:
            if isinstance(data, list) and len(data) > 100:
                risk_factors.append("High transaction count")
                risk_score += 10
        except Exception as e:
            logger.error(f"Error processing Tatum data: {e}")
        return {"risk_factors": risk_factors, "risk_score": risk_score}
    
    def _detect_suspicious_patterns(self, transactions: List) -> List[str]:
        patterns: List[str] = []
        if not transactions:
            return patterns
        recent_txs = transactions[:10]
        if len(recent_txs) >= 5:
            small_tx_count = sum(1 for tx in recent_txs if float(tx.get("value", 0)) < 1000000000000000)
            if small_tx_count >= 3:
                patterns.append("Multiple small incoming transactions")
        contract_interactions = sum(1 for tx in recent_txs if tx.get("to") and tx.get("to") != "")
        if contract_interactions > 5:
            patterns.append("High contract interaction frequency")
        if len(recent_txs) >= 3:
            try:
                timestamps = [int(tx.get("timeStamp", 0)) for tx in recent_txs[:3]]
                if len(timestamps) >= 2:
                    time_diff = timestamps[0] - timestamps[-1]
                    if time_diff < 300:
                        patterns.append("Rapid transaction sequence")
            except Exception:
                pass
        return patterns
    
    def _get_covalent_chain_id(self, chain: str) -> Optional[str]:
        chain_map = {
            "ethereum": "1",
            "polygon": "137",
            "bsc": "56",
            "avalanche": "43114",
            "arbitrum": "42161",
            "optimism": "10",
            "base": "8453",
            "linea": "59144",
            "scroll": "534352",
            "zksync": "324"
        }
        return chain_map.get(chain.lower())
    
    def is_valid_address(self, address: str) -> bool:
        if not address or not isinstance(address, str):
            return False
        if not address.startswith("0x") or len(address) != 42:
            return False
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False

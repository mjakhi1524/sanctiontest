import hashlib
import secrets
import time
import logging
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
import json
import os

logger = logging.getLogger(__name__)

class ConfirmationCodeSystem:
    def __init__(self):
        self.confirmation_codes = {}  # In-memory storage for active codes
        self.code_expiry = 3600  # 1 hour expiry
        self.max_attempts = 3
        self.attempt_tracking = {}  # Track failed attempts
        
        # Load existing codes from file if exists
        self.codes_file = "confirmation_codes.json"
        self._load_codes_from_file()
    
    def generate_confirmation_code(self, partner_id: str, address: str, action: str) -> str:
        """Generate a unique confirmation code for sanctions removal"""
        
        # Create a unique identifier
        unique_id = f"{partner_id}:{address}:{action}:{int(time.time())}"
        
        # Generate a random confirmation code
        confirmation_code = secrets.token_hex(8).upper()  # 16 character hex string
        
        # Store the code with metadata
        self.confirmation_codes[confirmation_code] = {
            "partner_id": partner_id,
            "address": address.lower(),
            "action": action,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=self.code_expiry)).isoformat(),
            "used": False,
            "attempts": 0
        }
        
        # Save to file
        self._save_codes_to_file()
        
        logger.info(f"Generated confirmation code for {action} on {address} by {partner_id}")
        
        return confirmation_code
    
    def verify_confirmation_code(self, confirmation_code: str, partner_id: str, address: str, action: str) -> Tuple[bool, str]:
        """Verify a confirmation code for sanctions removal"""
        
        if confirmation_code not in self.confirmation_codes:
            return False, "Invalid confirmation code"
        
        code_data = self.confirmation_codes[confirmation_code]
        
        # Check if code is expired
        expires_at = datetime.fromisoformat(code_data["expires_at"])
        if datetime.utcnow() > expires_at:
            # Remove expired code
            del self.confirmation_codes[confirmation_code]
            self._save_codes_to_file()
            return False, "Confirmation code has expired"
        
        # Check if code was already used
        if code_data["used"]:
            return False, "Confirmation code has already been used"
        
        # Check if code matches the intended action
        if code_data["partner_id"] != partner_id:
            return False, "Confirmation code does not match partner ID"
        
        if code_data["address"] != address.lower():
            return False, "Confirmation code does not match address"
        
        if code_data["action"] != action:
            return False, "Confirmation code does not match action"
        
        # Check for too many failed attempts
        if code_data["attempts"] >= self.max_attempts:
            # Remove code after too many failed attempts
            del self.confirmation_codes[confirmation_code]
            self._save_codes_to_file()
            return False, "Too many failed attempts, code has been invalidated"
        
        # Mark code as used
        code_data["used"] = True
        code_data["used_at"] = datetime.utcnow().isoformat()
        
        # Save updated codes
        self._save_codes_to_file()
        
        logger.info(f"Confirmation code verified for {action} on {address} by {partner_id}")
        
        return True, "Confirmation code verified successfully"
    
    def invalidate_confirmation_code(self, confirmation_code: str) -> bool:
        """Invalidate a confirmation code (e.g., after successful use)"""
        
        if confirmation_code in self.confirmation_codes:
            del self.confirmation_codes[confirmation_code]
            self._save_codes_to_file()
            logger.info(f"Confirmation code {confirmation_code} invalidated")
            return True
        
        return False
    
    def get_active_codes(self, partner_id: Optional[str] = None) -> Dict[str, dict]:
        """Get active confirmation codes, optionally filtered by partner_id"""
        
        active_codes = {}
        current_time = datetime.utcnow()
        
        for code, data in self.confirmation_codes.items():
            # Check if code is expired
            expires_at = datetime.fromisoformat(data["expires_at"])
            if current_time > expires_at:
                continue
            
            # Filter by partner_id if specified
            if partner_id and data["partner_id"] != partner_id:
                continue
            
            active_codes[code] = data
        
        return active_codes
    
    def cleanup_expired_codes(self) -> int:
        """Remove expired confirmation codes and return count of removed codes"""
        
        current_time = datetime.utcnow()
        expired_codes = []
        
        for code, data in self.confirmation_codes.items():
            expires_at = datetime.fromisoformat(data["expires_at"])
            if current_time > expires_at:
                expired_codes.append(code)
        
        # Remove expired codes
        for code in expired_codes:
            del self.confirmation_codes[code]
        
        if expired_codes:
            self._save_codes_to_file()
            logger.info(f"Cleaned up {len(expired_codes)} expired confirmation codes")
        
        return len(expired_codes)
    
    def _load_codes_from_file(self):
        """Load confirmation codes from file"""
        
        try:
            if os.path.exists(self.codes_file):
                with open(self.codes_file, "r", encoding="utf-8") as f:
                    loaded_codes = json.load(f)
                    
                    # Filter out expired codes
                    current_time = datetime.utcnow()
                    valid_codes = {}
                    
                    for code, data in loaded_codes.items():
                        expires_at = datetime.fromisoformat(data["expires_at"])
                        if current_time <= expires_at:
                            valid_codes[code] = data
                    
                    self.confirmation_codes = valid_codes
                    logger.info(f"Loaded {len(valid_codes)} valid confirmation codes from file")
                    
        except Exception as e:
            logger.error(f"Failed to load confirmation codes from file: {e}")
            self.confirmation_codes = {}
    
    def _save_codes_to_file(self):
        """Save confirmation codes to file"""
        
        try:
            with open(self.codes_file, "w", encoding="utf-8") as f:
                json.dump(self.confirmation_codes, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save confirmation codes to file: {e}")

class EnhancedConfirmationSystem(ConfirmationCodeSystem):
    """Enhanced confirmation system with additional security features"""
    
    def __init__(self):
        super().__init__()
        self.rate_limit_window = 300  # 5 minutes
        self.max_codes_per_window = 5
        self.rate_limit_tracking = {}  # Track rate limiting per partner
    
    def generate_confirmation_code(self, partner_id: str, address: str, action: str) -> str:
        """Generate confirmation code with rate limiting"""
        
        # Check rate limiting
        if not self._check_rate_limit(partner_id):
            raise Exception("Rate limit exceeded. Too many confirmation code requests.")
        
        # Generate the code
        code = super().generate_confirmation_code(partner_id, address, action)
        
        # Update rate limiting
        self._update_rate_limit(partner_id)
        
        return code
    
    def _check_rate_limit(self, partner_id: str) -> bool:
        """Check if partner has exceeded rate limit for confirmation codes"""
        
        current_time = time.time()
        
        if partner_id not in self.rate_limit_tracking:
            return True
        
        # Clean old entries
        self.rate_limit_tracking[partner_id] = [
            timestamp for timestamp in self.rate_limit_tracking[partner_id]
            if current_time - timestamp < self.rate_limit_window
        ]
        
        # Check if under limit
        return len(self.rate_limit_tracking[partner_id]) < self.max_codes_per_window
    
    def _update_rate_limit(self, partner_id: str):
        """Update rate limiting tracking for partner"""
        
        current_time = time.time()
        
        if partner_id not in self.rate_limit_tracking:
            self.rate_limit_tracking[partner_id] = []
        
        self.rate_limit_tracking[partner_id].append(current_time)
    
    def require_admin_approval(self, partner_id: str, address: str, risk_score: int) -> bool:
        """Check if admin approval is required for high-risk sanctions operations"""
        
        # Require admin approval for:
        # 1. High risk scores (>80)
        # 2. Multiple sanctions operations in short time
        # 3. Large value addresses
        
        if risk_score > 80:
            return True
        
        # Check recent sanctions operations by this partner
        recent_operations = self._get_recent_operations(partner_id)
        if len(recent_operations) > 10:  # More than 10 operations in 24 hours
            return True
        
        return False
    
    def _get_recent_operations(self, partner_id: str, hours: int = 24) -> list:
        """Get recent sanctions operations by partner"""
        
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(hours=hours)
        
        recent_ops = []
        
        for code, data in self.confirmation_codes.items():
            if data["partner_id"] == partner_id:
                created_at = datetime.fromisoformat(data["created_at"])
                if created_at >= cutoff_time:
                    recent_ops.append(data)
        
        return recent_ops

# Global instance
confirmation_system = EnhancedConfirmationSystem()

def verify_removal_confirmation(confirmation_code: str, address: str) -> bool:
    """Helper function to verify removal confirmation"""
    
    # This is a simplified verification - in practice, you'd pass more context
    try:
        # For now, we'll just check if the code exists and is valid
        if confirmation_code in confirmation_system.confirmation_codes:
            code_data = confirmation_system.confirmation_codes[confirmation_code]
            
            # Check if code is expired
            expires_at = datetime.fromisoformat(code_data["expires_at"])
            if datetime.utcnow() > expires_at:
                return False
            
            # Check if code was already used
            if code_data["used"]:
                return False
            
            # Check if address matches
            if code_data["address"] != address.lower():
                return False
            
            return True
            
    except Exception as e:
        logger.error(f"Error verifying removal confirmation: {e}")
        return False
    
    return False

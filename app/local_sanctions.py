"""
Local sanctions checker that reads from a JSON file instead of querying Supabase
"""

import json
import os
from pathlib import Path
from typing import Set, Optional


class LocalSanctionsChecker:
    """Local sanctions checker using JSON file instead of database queries"""
    
    def __init__(self, file_path: Optional[str] = None):
        """Initialize with path to sanctioned wallets JSON file"""
        if file_path is None:
            # Default to the sanctioned_wallets.json in the relay-api directory
            current_dir = Path(__file__).parent.parent
            file_path = current_dir / "sanctioned_wallets.json"
        
        self.file_path = Path(file_path)
        self._sanctioned_addresses: Set[str] = set()
        self._last_modified = 0
        self._load_sanctioned_addresses()
    
    def _load_sanctioned_addresses(self) -> None:
        """Load sanctioned addresses from JSON file"""
        try:
            if not self.file_path.exists():
                print(f"⚠️  Warning: Sanctioned wallets file not found at {self.file_path}")
                print("   Creating empty sanctioned wallets list")
                self._create_default_file()
                return
            
            # Check if file has been modified
            current_mtime = self.file_path.stat().st_mtime
            if current_mtime <= self._last_modified:
                return  # No need to reload
            
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract addresses and normalize them (lowercase)
            addresses = data.get('sanctioned_addresses', [])
            self._sanctioned_addresses = {addr.lower() for addr in addresses if addr}
            self._last_modified = current_mtime
            
            print(f"✅ Loaded {len(self._sanctioned_addresses)} sanctioned addresses from {self.file_path}")
            
        except Exception as e:
            print(f"❌ Error loading sanctioned wallets: {e}")
            self._sanctioned_addresses = set()
    
    def _create_default_file(self) -> None:
        """Create a default sanctioned wallets file if none exists"""
        try:
            default_data = {
                "sanctioned_addresses": [
                    "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",
                    "0x983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2",
                    "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40"
                ],
                "last_updated": "2025-01-20T00:00:00Z",
                "description": "Default sanctioned wallets list - update manually as needed",
                "total_count": 3
            }
            
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, indent=2)
            
            self._sanctioned_addresses = {addr.lower() for addr in default_data["sanctioned_addresses"]}
            self._last_modified = self.file_path.stat().st_mtime
            
            print(f"✅ Created default sanctioned wallets file at {self.file_path}")
            
        except Exception as e:
            print(f"❌ Error creating default file: {e}")
    
    def is_sanctioned(self, address: str) -> bool:
        """Check if an address is sanctioned"""
        if not address:
            return False
        
        # Reload file if it has been modified
        self._load_sanctioned_addresses()
        
        # Normalize address and check
        normalized_addr = address.lower()
        is_sanctioned = normalized_addr in self._sanctioned_addresses
        
        if is_sanctioned:
            print(f"🚫 SANCTIONED WALLET DETECTED: {address}")
        else:
            print(f"✅ Wallet {address} is clean (not sanctioned)")
        
        return is_sanctioned
    
    def get_sanctioned_count(self) -> int:
        """Get the total number of sanctioned addresses"""
        self._load_sanctioned_addresses()
        return len(self._sanctioned_addresses)
    
    def reload(self) -> None:
        """Force reload of sanctioned addresses from file"""
        self._last_modified = 0
        self._load_sanctioned_addresses()
    
    def add_sanctioned_address(self, address: str) -> bool:
        """Add a new sanctioned address to the file"""
        try:
            if not address or not address.startswith('0x'):
                return False
            
            # Reload current data
            self._load_sanctioned_addresses()
            
            # Add new address
            if address.lower() not in self._sanctioned_addresses:
                self._sanctioned_addresses.add(address.lower())
                
                # Read current file
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Update data
                data['sanctioned_addresses'] = list(self._sanctioned_addresses)
                data['total_count'] = len(self._sanctioned_addresses)
                
                # Write back to file
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                self._last_modified = self.file_path.stat().st_mtime
                print(f"✅ Added sanctioned address: {address}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error adding sanctioned address: {e}")
            return False

    def remove_sanctioned_address(self, address: str) -> bool:
        """Remove a sanctioned address from the file"""
        try:
            if not address or not address.startswith('0x'):
                return False
            
            # Reload current data
            self._load_sanctioned_addresses()
            
            # Remove address
            normalized_addr = address.lower()
            if normalized_addr in self._sanctioned_addresses:
                self._sanctioned_addresses.remove(normalized_addr)
                
                # Read current file
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Update data
                data['sanctioned_addresses'] = list(self._sanctioned_addresses)
                data['total_count'] = len(self._sanctioned_addresses)
                
                # Write back to file
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                self._last_modified = self.file_path.stat().st_mtime
                print(f"✅ Removed sanctioned address: {address}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error removing sanctioned address: {e}")
            return False


# Global instance for use in main.py
local_sanctions_checker = LocalSanctionsChecker()

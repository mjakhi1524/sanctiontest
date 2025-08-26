#!/usr/bin/env python3
"""
Test script to verify sanctions checking functionality
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from sanctions import SanctionsChecker
from supabase_client import get_supabase

async def test_sanctions_checker():
    """Test the sanctions checker functionality"""
    print("🔍 Testing Sanctions Checker...")
    
    # Test addresses
    test_addresses = [
        "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",  # Known sanctioned address from api.txt
        "0x983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2",  # Known sanctioned address from api.txt
        "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40",  # Known sanctioned address from api.txt
        "0x742d35Cc6645C0532979A1f8A4D5fB2C61a8BaF6",  # Clean test address from api.txt
        "0x1234567890123456789012345678901234567890",  # Random test address
    ]
    
    # Initialize sanctions checker
    sanctions_checker = SanctionsChecker()
    await sanctions_checker.load_initial()
    
    print("\n📋 Testing individual address checks:")
    for addr in test_addresses:
        try:
            is_sanctioned = await sanctions_checker.is_sanctioned(addr)
            status = "🚫 SANCTIONED" if is_sanctioned else "✅ CLEAN"
            print(f"  {addr}: {status}")
        except Exception as e:
            print(f"  {addr}: ❌ ERROR - {e}")
    
    # Test database connection and table contents
    print("\n🗄️  Checking database connection and table contents:")
    try:
        sb = get_supabase()
        
        # Check if sanctioned_wallets table exists and has data
        print("  Checking sanctioned_wallets table...")
        res = sb.table("sanctioned_wallets").select("address, created_at").limit(5).execute()
        rows = res.data or []
        
        if rows:
            print(f"  ✅ Found {len(rows)} records in sanctioned_wallets table:")
            for row in rows:
                print(f"    - {row.get('address')} (created: {row.get('created_at')})")
        else:
            print("  ⚠️  sanctioned_wallets table is empty - no addresses to check against!")
            print("  💡 You need to add some test addresses to test the sanctions checking.")
        
        # Check table structure
        print("\n  Checking table structure...")
        try:
            # Try to get column info by selecting all columns
            res = sb.table("sanctioned_wallets").select("*").limit(1).execute()
            if res.data:
                columns = list(res.data[0].keys()) if res.data else []
                print(f"  ✅ Table columns: {', '.join(columns)}")
            else:
                print("  ℹ️  Table exists but has no data")
        except Exception as e:
            print(f"  ❌ Error checking table structure: {e}")
            
    except Exception as e:
        print(f"  ❌ Database connection error: {e}")
        print("  💡 Make sure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set correctly")

async def test_risk_model():
    """Test the risk model functionality"""
    print("\n🎯 Testing Risk Model...")
    
    try:
        from risk_model import compute_risk_score, FeatureHit
        from datetime import datetime, timezone
        
        # Create test feature hits
        test_hits = [
            FeatureHit(
                key="test_sanctioned",
                base=100.0,
                occurred_at=datetime.now(timezone.utc),
                critical=True,
                details={"source": "test"}
            )
        ]
        
        # Test risk computation
        score, band, reasons, applied = compute_risk_score(
            hits=test_hits,
            sanctions_match=True,  # Simulate sanctioned address
            transaction_context={"data_size": 1000},
            network_context={"chain": "ethereum"}
        )
        
        print(f"  ✅ Risk computation working:")
        print(f"    - Score: {score}")
        print(f"    - Band: {band}")
        print(f"    - Reasons: {reasons}")
        
    except Exception as e:
        print(f"  ❌ Risk model error: {e}")

async def main():
    """Main test function"""
    print("🚀 Relay API Sanctions Checker Test")
    print("=" * 50)
    
    # Check environment variables
    print("\n🔧 Environment Check:")
    required_vars = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]
    for var in required_vars:
        value = os.getenv(var)
        if value:
            # Mask the key for security
            if "KEY" in var:
                masked = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
                print(f"  ✅ {var}: {masked}")
            else:
                print(f"  ✅ {var}: {value}")
        else:
            print(f"  ❌ {var}: NOT SET")
    
    # Run tests
    await test_sanctions_checker()
    await test_risk_model()
    
    print("\n" + "=" * 50)
    print("✨ Test completed!")

if __name__ == "__main__":
    asyncio.run(main())

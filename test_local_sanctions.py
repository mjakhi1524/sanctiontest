#!/usr/bin/env python3
"""
Test script to verify local sanctions checker functionality
"""

import sys
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from local_sanctions import LocalSanctionsChecker

def test_sanctions_checker():
    """Test the local sanctions checker"""
    print("🔍 Testing Local Sanctions Checker...")
    
    # Initialize checker
    checker = LocalSanctionsChecker()
    
    # Test addresses
    test_addresses = [
        "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c",  # Should be sanctioned
        "0x983a81ca6FB1e441266D2FbcB7D8E530AC2E05A2",  # Should be sanctioned
        "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40",  # Should be sanctioned
        "0x742d35Cc6645C0532979A1f8A4D5fB2C61a8BaF6",  # Should be clean
        "0x1234567890123456789012345678901234567890",  # Should be clean
    ]
    
    print(f"\n📋 Testing {len(test_addresses)} addresses:")
    for addr in test_addresses:
        is_sanctioned = checker.is_sanctioned(addr)
        status = "🚫 SANCTIONED" if is_sanctioned else "✅ CLEAN"
        print(f"  {addr}: {status}")
    
    # Test adding a new address
    print(f"\n➕ Testing add functionality:")
    new_addr = "0x9999999999999999999999999999999999999999"
    success = checker.add_sanctioned_address(new_addr)
    print(f"  Added {new_addr}: {'✅ Success' if success else '❌ Failed'}")
    
    # Verify it was added
    is_sanctioned = checker.is_sanctioned(new_addr)
    print(f"  Verification: {new_addr} is now {'🚫 SANCTIONED' if is_sanctioned else '✅ CLEAN'}")
    
    # Test removing the address
    print(f"\n➖ Testing remove functionality:")
    success = checker.remove_sanctioned_address(new_addr)
    print(f"  Removed {new_addr}: {'✅ Success' if success else '❌ Failed'}")
    
    # Verify it was removed
    is_sanctioned = checker.is_sanctioned(new_addr)
    print(f"  Verification: {new_addr} is now {'🚫 SANCTIONED' if is_sanctioned else '✅ CLEAN'}")
    
    # Show final stats
    print(f"\n📊 Final Statistics:")
    print(f"  Total sanctioned addresses: {checker.get_sanctioned_count()}")
    print(f"  File path: {checker.file_path}")
    print(f"  File exists: {checker.file_path.exists()}")

if __name__ == "__main__":
    print("🚀 Local Sanctions Checker Test")
    print("=" * 50)
    
    try:
        test_sanctions_checker()
        print("\n" + "=" * 50)
        print("✨ All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()



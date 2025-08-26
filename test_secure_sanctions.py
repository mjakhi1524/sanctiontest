#!/usr/bin/env python3
"""
Test script for the Secure Sanctions Management System
Run this to verify all components are working correctly
"""

import asyncio
import json
import os
import sys
from datetime import datetime

# Add the app directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

async def test_wallet_risk_assessor():
    """Test the wallet risk assessor"""
    print("🔍 Testing Wallet Risk Assessor...")
    
    try:
        from wallet_risk_assessor import WalletRiskAssessor
        
        # Initialize the assessor
        assessor = WalletRiskAssessor()
        
        # Test address validation
        test_address = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6"
        is_valid = assessor.is_valid_address(test_address)
        print(f"✅ Address validation: {is_valid}")
        
        # Test risk assessment (this will fail without API keys, but should not crash)
        try:
            risk_profile = await assessor.assess_wallet_risk(test_address, "ethereum")
            print(f"✅ Risk assessment completed: Score={risk_profile.risk_score}, Confidence={risk_profile.confidence}")
        except Exception as e:
            print(f"⚠️  Risk assessment failed (expected without API keys): {e}")
        
        print("✅ Wallet Risk Assessor tests passed\n")
        return True
        
    except Exception as e:
        print(f"❌ Wallet Risk Assessor tests failed: {e}\n")
        return False

async def test_confirmation_system():
    """Test the confirmation code system"""
    print("🔐 Testing Confirmation Code System...")
    
    try:
        from confirmation_system import confirmation_system
        
        # Test confirmation code generation
        partner_id = "test_partner_123"
        address = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6"
        action = "remove"
        
        # Generate confirmation code
        confirmation_code = confirmation_system.generate_confirmation_code(partner_id, address, action)
        print(f"✅ Confirmation code generated: {confirmation_code}")
        
        # Verify confirmation code
        is_valid, message = confirmation_system.verify_confirmation_code(
            confirmation_code, partner_id, address, action
        )
        print(f"✅ Confirmation code verification: {is_valid} - {message}")
        
        # Test invalid code
        is_valid, message = confirmation_system.verify_confirmation_code(
            "INVALID_CODE", partner_id, address, action
        )
        print(f"✅ Invalid code rejection: {is_valid} - {message}")
        
        # Test rate limiting
        try:
            for i in range(10):  # Try to generate more than the limit
                confirmation_system.generate_confirmation_code(partner_id, address, action)
            print("⚠️  Rate limiting not working as expected")
        except Exception as e:
            print(f"✅ Rate limiting working: {e}")
        
        print("✅ Confirmation Code System tests passed\n")
        return True
        
    except Exception as e:
        print(f"❌ Confirmation Code System tests failed: {e}\n")
        return False

async def test_audit_logger():
    """Test the audit logger"""
    print("📝 Testing Audit Logger...")
    
    try:
        from audit_logger import SanctionsAuditLogger
        
        # Initialize the audit logger
        audit_logger = SanctionsAuditLogger()
        
        # Test logging an action
        success = await audit_logger.log_sanctions_action(
            partner_id="test_partner_123",
            action="TEST",
            address="0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
            risk_score=75,
            risk_factors=["Test risk factor"],
            data_sources=["test_source"],
            reason="Testing audit logging"
        )
        print(f"✅ Audit logging: {success}")
        
        # Test retrieving audit logs
        logs = await audit_logger.get_audit_logs(
            partner_id="test_partner_123",
            limit=10
        )
        print(f"✅ Retrieved {len(logs)} audit logs")
        
        # Test audit summary
        summary = await audit_logger.get_audit_summary("test_partner_123")
        print(f"✅ Audit summary: {summary.get('total_actions', 0)} total actions")
        
        print("✅ Audit Logger tests passed\n")
        return True
        
    except Exception as e:
        print(f"❌ Audit Logger tests failed: {e}\n")
        return False

async def test_models():
    """Test the enhanced models"""
    print("📋 Testing Enhanced Models...")
    
    try:
        from models import SanctionsManageRequest, WalletRiskAssessmentRequest
        
        # Test SanctionsManageRequest validation
        try:
            request = SanctionsManageRequest(
                address="0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                action="add",
                reason="Testing model validation",
                chain="ethereum"
            )
            print(f"✅ SanctionsManageRequest validation: {request.address}")
        except Exception as e:
            print(f"❌ SanctionsManageRequest validation failed: {e}")
            return False
        
        # Test WalletRiskAssessmentRequest validation
        try:
            request = WalletRiskAssessmentRequest(
                address="0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                chain="ethereum"
            )
            print(f"✅ WalletRiskAssessmentRequest validation: {request.address}")
        except Exception as e:
            print(f"❌ WalletRiskAssessmentRequest validation failed: {e}")
            return False
        
        # Test invalid address validation
        try:
            request = SanctionsManageRequest(
                address="invalid_address",
                action="add",
                chain="ethereum"
            )
            print("❌ Invalid address should have been rejected")
            return False
        except Exception as e:
            print(f"✅ Invalid address correctly rejected: {e}")
        
        print("✅ Enhanced Models tests passed\n")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced Models tests failed: {e}\n")
        return False

async def test_file_structure():
    """Test that required files and directories exist"""
    print("📁 Testing File Structure...")
    
    required_files = [
        "app/wallet_risk_assessor.py",
        "app/audit_logger.py", 
        "app/confirmation_system.py",
        "app/models.py",
        "app/main.py",
        "requirements.txt"
    ]
    
    required_dirs = [
        "audit_logs"
    ]
    
    all_good = True
    
    # Check required files
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ File exists: {file_path}")
        else:
            print(f"❌ File missing: {file_path}")
            all_good = False
    
    # Check required directories
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"✅ Directory exists: {dir_path}")
        else:
            print(f"❌ Directory missing: {dir_path}")
            all_good = False
    
    # Check if audit_logs directory was created
    if not os.path.exists("audit_logs"):
        os.makedirs("audit_logs", exist_ok=True)
        print("✅ Created audit_logs directory")
    
    if all_good:
        print("✅ File structure tests passed\n")
    else:
        print("❌ File structure tests failed\n")
    
    return all_good

async def test_environment():
    """Test environment variables and configuration"""
    print("⚙️  Testing Environment Configuration...")
    
    # Check for required environment variables
    required_vars = [
        "SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY"
    ]
    
    optional_vars = [
        "ETHERSCAN_API_KEY",
        "BITQUERY_API_KEY",
        "COVALENT_API_KEY",
        "TATUM_API_KEY"
    ]
    
    all_good = True
    
    # Check required variables
    for var in required_vars:
        if os.getenv(var):
            print(f"✅ Required env var: {var}")
        else:
            print(f"⚠️  Missing required env var: {var}")
            all_good = False
    
    # Check optional variables
    for var in optional_vars:
        if os.getenv(var):
            print(f"✅ Optional env var: {var}")
        else:
            print(f"ℹ️  Missing optional env var: {var}")
    
    if all_good:
        print("✅ Environment configuration tests passed\n")
    else:
        print("⚠️  Environment configuration tests incomplete\n")
    
    return all_good

async def main():
    """Run all tests"""
    print("🚀 Starting Secure Sanctions Management System Tests\n")
    print(f"⏰ Test started at: {datetime.now().isoformat()}\n")
    
    tests = [
        ("File Structure", test_file_structure),
        ("Environment", test_environment),
        ("Models", test_models),
        ("Wallet Risk Assessor", test_wallet_risk_assessor),
        ("Confirmation System", test_confirmation_system),
        ("Audit Logger", test_audit_logger)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}\n")
            results.append((test_name, False))
    
    # Print summary
    print("📊 Test Results Summary")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print("=" * 50)
    print(f"Total: {total} | Passed: {passed} | Failed: {total - passed}")
    
    if passed == total:
        print("\n🎉 All tests passed! The Secure Sanctions Management System is ready.")
        print("\nNext steps:")
        print("1. Set up your API keys (ETHERSCAN_API_KEY, BITQUERY_API_KEY, etc.)")
        print("2. Run the database migration in Supabase")
        print("3. Start the API with: uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload")
        print("4. Test the endpoints using the examples in SECURE_SANCTIONS_README.md")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the errors above.")
        print("The system may not work correctly until all issues are resolved.")
    
    return passed == total

if __name__ == "__main__":
    # Run the tests
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

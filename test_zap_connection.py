"""Test ZAP connection with mixed environment"""
import requests

# Try different ZAP import methods
zap_client = None
try:
    from zapv2 import ZAPv2
    zap_client = ZAPv2
    print("✅ Using zapv2 import")
except ImportError:
    print("⚠️ zapv2 not available, will use HTTP API")

def test_zap_connection():
    print("🔍 Testing ZAP connection...")
    
    try:
        # Test HTTP API first
        response = requests.get("http://localhost:8080/JSON/core/view/version/", timeout=10)
        if response.status_code == 200:
            version_data = response.json()
            print(f"✅ ZAP HTTP API works: {version_data}")
        else:
            print(f"❌ ZAP API returned: {response.status_code}")
            return False
        
        # Test Python client if available
        if zap_client:
            zap = zap_client(proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
            version = zap.core.version
            print(f"✅ ZAP Python client works: {version}")
        else:
            print("✅ Will use HTTP API for ZAP communication")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 ZAP Connection Test")
    print("=" * 30)
    
    success = test_zap_connection()
    
    if success:
        print("\n🎉 ZAP connection ready!")
        print("Next: Start ZAP daemon in another terminal")
        print("Command: ./ZAP_2.15.0/zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true")
    else:
        print("\n❌ Start ZAP daemon first!")

"""Flexible ZAP Collector - With Persistent ChromaDB Storage"""
import time
import requests
from typing import Dict, Any
import chromadb
from sentence_transformers import SentenceTransformer
import os

# Try to import ZAP client
try:
    from zapv2 import ZAPv2
    ZAP_CLIENT_AVAILABLE = True
except ImportError:
    ZAP_CLIENT_AVAILABLE = False
    print("⚠️ ZAP Python client not available, using HTTP API")

class ZAPCollector:
    def __init__(self):
        print("🔧 Initializing ZAP Collector...")
        
        self.zap_api_url = "http://localhost:8080"
        
        # Initialize ChromaDB with persistent storage
        print("📊 Setting up ChromaDB with persistent storage...")
        
        # Create data directory
        data_dir = "./chroma_db"
        os.makedirs(data_dir, exist_ok=True)
        
        # Use persistent ChromaDB client
        self.chroma_client = chromadb.PersistentClient(path=data_dir)
        
        try:
            self.collection = self.chroma_client.get_collection("security_knowledge")
            print("✅ Using existing ChromaDB collection")
        except:
            self.collection = self.chroma_client.create_collection(
                name="security_knowledge",
                metadata={"description": "Security knowledge base"}
            )
            print("✅ Created new ChromaDB collection")
        
        # Initialize embedding model
        print("🤖 Loading embedding model...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Setup ZAP connection
        self.setup_zap_connection()

    def setup_zap_connection(self):
        """Setup ZAP connection (Python client or HTTP API)"""
        print("🔗 Connecting to ZAP...")
        
        try:
            # Test basic HTTP connection
            response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=5)
            if response.status_code != 200:
                raise Exception("ZAP not responding")
            
            version = response.json().get('version', 'Unknown')
            print(f"✅ ZAP HTTP API connected - Version: {version}")
            
            # Try Python client if available
            if ZAP_CLIENT_AVAILABLE:
                self.zap = ZAPv2(proxies={'http': self.zap_api_url, 'https': self.zap_api_url})
                self.use_python_client = True
                print("✅ Using ZAP Python client")
            else:
                self.zap = None
                self.use_python_client = False
                print("✅ Using ZAP HTTP API")
                
        except Exception as e:
            print(f"❌ ZAP connection failed: {e}")
            raise

    def get_message_count(self) -> int:
        """Get message count from ZAP"""
        try:
            if self.use_python_client and self.zap:
                return int(self.zap.core.number_of_messages())
            else:
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/numberOfMessages/")
                return int(response.json().get('numberOfMessages', '0'))
        except:
            return 0

    def get_message(self, msg_id: int) -> Dict[str, Any]:
        """Get specific message from ZAP"""
        try:
            if self.use_python_client and self.zap:
                return self.zap.core.message(str(msg_id))
            else:
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/message/", 
                                      params={'id': str(msg_id)})
                data = response.json()
                return data.get('message', {}) if isinstance(data, dict) else {}
        except:
            return {}

    def index_security_knowledge(self):
        """Index baseline security knowledge"""
        print("📚 Indexing security knowledge...")
        
        # Check if already indexed
        try:
            existing_count = self.collection.count()
            if existing_count >= 10:
                print(f"✅ Security knowledge already indexed ({existing_count} documents)")
                return
        except:
            pass
        
        security_docs = [
            "SQL injection vulnerability occurs when user input is not properly sanitized in database queries allowing attackers to execute malicious SQL commands",
            "Cross-site scripting XSS allows malicious scripts execution in web browsers through unvalidated input enabling code injection attacks",
            "API keys and authentication tokens should never be exposed in URLs or client-side code as they provide unauthorized access",
            "HTTPS encryption should be enforced for all sensitive data transmission and authentication to prevent man-in-the-middle attacks",
            "Input validation must be implemented on both client and server sides to prevent injection attacks and data corruption",
            "Authentication sessions should have proper timeout and secure storage mechanisms implemented to prevent session hijacking",
            "CSRF protection using tokens prevents unauthorized state-changing operations in web applications by validating request origin",
            "Security headers like CSP and X-Frame-Options provide additional protection against web attacks and clickjacking",
            "Sensitive data including passwords should never be stored in plain text or logged to files for security compliance",
            "Authorization checks must be implemented for all protected resources and operations to enforce proper access control"
        ]
        
        embeddings = self.embedding_model.encode(security_docs)
        ids = [f"security_baseline_{i}" for i in range(len(security_docs))]
        metadatas = [{"type": "security_knowledge", "source": "baseline"} for _ in security_docs]
        
        # Add to persistent collection
        self.collection.add(
            embeddings=embeddings.tolist(),
            documents=security_docs,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✅ Indexed {len(security_docs)} security documents")

    def generate_sample_traffic(self):
        """Generate sample traffic through ZAP proxy"""
        print("🎯 Generating sample traffic...")
        
        proxies = {'http': self.zap_api_url, 'https': self.zap_api_url}
        
        test_requests = [
            ('GET', 'http://httpbin.org/get'),
            ('POST', 'http://httpbin.org/post', {'username': 'admin', 'password': 'secret123'}),
            ('GET', 'http://httpbin.org/json'),
            ('GET', 'http://httpbin.org/get?api_key=12345&token=secret'),
            ('POST', 'http://httpbin.org/post', {'email': 'user@test.com', 'api_key': 'abc123'}),
            ('GET', 'http://httpbin.org/headers'),
        ]
        
        successful = 0
        for req_data in test_requests:
            try:
                if len(req_data) == 2:
                    method, url = req_data
                    response = requests.get(url, proxies=proxies, timeout=10, verify=False)
                else:
                    method, url, data = req_data
                    response = requests.post(url, data=data, proxies=proxies, timeout=10, verify=False)
                
                if response.status_code == 200:
                    successful += 1
                    print(f"  ✅ {method} {url[:50]}...")
                else:
                    print(f"  ❌ {method} - Error {response.status_code}")
                    
            except Exception as e:
                print(f"  ❌ {method} - Error")
        
        print(f"✅ Generated {successful} requests")
        return successful

    def analyze_request_security(self, content: str, url: str, method: str) -> list:
        """Analyze request for security issues"""
        issues = []
        content_lower = content.lower()
        
        if any(term in content_lower for term in ['password', 'passwd', 'pwd']):
            issues.append('contains_password')
        if any(term in content_lower for term in ['api_key', 'token', 'secret']):
            issues.append('contains_sensitive_data')
        if any(term in content_lower for term in ['select ', 'union ', 'drop ', 'insert ']):
            issues.append('potential_sql_injection')
        if '<script' in content_lower or 'javascript:' in content_lower:
            issues.append('potential_xss')
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            issues.append('state_changing_request')
        if not url.startswith('https://'):
            issues.append('unencrypted_request')
            
        return issues

    def process_zap_message(self, msg_id: int, message: Dict[str, Any]) -> bool:
        """Process ZAP message and store in ChromaDB"""
        try:
            # Check if message is valid
            if not message or not isinstance(message, dict):
                return False
                
            request_header = message.get('requestHeader', '')
            request_body = message.get('requestBody', '')
            response_header = message.get('responseHeader', '')
            
            # Parse request details
            first_line = request_header.split('\n')[0] if request_header else ''
            parts = first_line.split(' ')
            method = parts[0] if parts else 'UNKNOWN'
            url = parts[1] if len(parts) > 1 else 'UNKNOWN'
            
            # Skip if URL is empty or invalid
            if url == 'UNKNOWN' or not url:
                return False
            
            # Create analysis document
            analysis_doc = f"""HTTP {method} Request Security Analysis

URL: {url}
METHOD: {method}

REQUEST HEADERS:
{request_header}

REQUEST BODY:
{request_body}

RESPONSE HEADERS:
{response_header[:300]}

Security Analysis Context:
- Examine for sensitive data exposure in URL parameters and request body
- Check authentication and authorization mechanisms
- Verify secure communication protocols (HTTPS vs HTTP)  
- Identify potential injection vulnerabilities
- Analyze security-related response headers"""

            # Analyze security issues
            all_content = f"{request_body} {url} {request_header}"
            security_issues = self.analyze_request_security(all_content, url, method)
            
            # Create embedding
            embedding = self.embedding_model.encode([analysis_doc])[0]
            
            # Create unique ID
            doc_id = f"http_req_{msg_id}_{int(time.time())}"
            
            # Store in ChromaDB
            metadata = {
                "type": "http_request",
                "method": method,
                "url": url[:80],
                "msg_id": str(msg_id),
                "security_issues": ','.join(security_issues) if security_issues else 'none',
                "timestamp": int(time.time())
            }
            
            self.collection.add(
                embeddings=[embedding.tolist()],
                documents=[analysis_doc],
                metadatas=[metadata],
                ids=[doc_id]
            )
            
            return True
            
        except Exception as e:
            print(f"❌ Error processing message {msg_id}: {e}")
            return False

    def monitor_traffic(self):
        """Monitor and process ZAP traffic"""
        print("\n🚀 Starting traffic monitoring...")
        print("📡 ZAP proxy: localhost:8080")
        print("⏹️  Press Ctrl+C to stop\n")
        
        # Generate sample traffic
        self.generate_sample_traffic()
        time.sleep(8)  # Wait for ZAP processing
        
        last_count = 0
        processed = 0
        
        try:
            while True:
                current_count = self.get_message_count()
                
                if current_count > last_count:
                    new_msgs = current_count - last_count
                    print(f"📥 Processing {new_msgs} new messages...")
                    
                    for msg_id in range(last_count, current_count):
                        message = self.get_message(msg_id)
                        if message and self.process_zap_message(msg_id, message):
                            processed += 1
                    
                    last_count = current_count
                    print(f"✅ Processed: {processed} | Total: {current_count}")
                
                time.sleep(3)
        
        except KeyboardInterrupt:
            print(f"\n🛑 Monitoring stopped")
            print(f"📊 Processed {processed} requests")
            print(f"📚 ChromaDB has {self.collection.count()} documents")
            print(f"💾 Data saved to: ./chroma_db/")

def main():
    try:
        collector = ZAPCollector()
        collector.index_security_knowledge()
        collector.monitor_traffic()
    except KeyboardInterrupt:
        print("\n👋 Collector stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

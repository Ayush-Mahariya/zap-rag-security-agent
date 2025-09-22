"""Direct OpenAI Integration for Security Analysis - With Persistent ChromaDB"""
import os
import openai
import chromadb
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any

class OpenAISecurityAnalyzer:
    def __init__(self):
        print("🔧 Initializing OpenAI Security Analyzer...")
        
        # Setup OpenAI
        self.setup_openai()
        
        # Connect to persistent ChromaDB
        print("📊 Connecting to persistent ChromaDB...")
        data_dir = "./chroma_db"
        
        try:
            self.chroma_client = chromadb.PersistentClient(path=data_dir)
            self.collection = self.chroma_client.get_collection("security_knowledge")
            print("✅ Connected to security knowledge base")
        except Exception as e:
            print(f"❌ Failed to connect to ChromaDB: {e}")
            print("💡 Run the collector first to create the knowledge base")
            raise
        
        # Load embedding model
        print("🤖 Loading embedding model...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        print("✅ OpenAI Security Analyzer ready!")
    
    def setup_openai(self):
        """Setup OpenAI configuration"""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise Exception("OPENAI_API_KEY environment variable not set!")
        
        # Set OpenAI API key
        openai.api_key = api_key
        self.client = openai.OpenAI(api_key=api_key)
        print("✅ OpenAI GPT-4 connection ready")
    
    def query_security_knowledge(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Query security knowledge using RAG"""
        try:
            query_embedding = self.embedding_model.encode([query])[0]
            
            results = self.collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )
            
            knowledge = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    knowledge.append({
                        'content': doc,
                        'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                        'relevance_score': 1 - results['distances'][0][i] if results['distances'] else 0.0
                    })
            
            return knowledge
            
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
    
    def prepare_security_context(self, knowledge: List[Dict[str, Any]]) -> str:
        """Prepare security context for GPT-4"""
        http_requests = []
        security_baseline = []
        security_issues = {}
        
        for item in knowledge:
            metadata = item.get('metadata', {})
            
            if metadata.get('type') == 'http_request':
                http_requests.append(item)
                issues = metadata.get('security_issues', '').split(',')
                for issue in issues:
                    issue = issue.strip()
                    if issue and issue != 'none':
                        security_issues[issue] = security_issues.get(issue, 0) + 1
                        
            elif metadata.get('type') == 'security_knowledge':
                security_baseline.append(item)
        
        # Build context
        context_parts = []
        context_parts.append(f"HTTP TRAFFIC ANALYSIS DATA:")
        context_parts.append(f"- Total requests analyzed: {len(http_requests)}")
        
        if security_issues:
            context_parts.append(f"\nSECURITY ISSUES DETECTED:")
            for issue, count in security_issues.items():
                context_parts.append(f"- {issue.replace('_', ' ').title()}: {count} instances")
        
        context_parts.append(f"\nSAMPLE HTTP REQUESTS:")
        for i, req in enumerate(http_requests[:5], 1):
            metadata = req.get('metadata', {})
            method = metadata.get('method', 'UNKNOWN')
            url = metadata.get('url', 'UNKNOWN')
            issues = metadata.get('security_issues', 'none')
            context_parts.append(f"{i}. {method} {url}")
            if issues != 'none':
                context_parts.append(f"   Security flags: {issues}")
        
        if security_baseline:
            context_parts.append(f"\nRELEVANT SECURITY KNOWLEDGE:")
            for knowledge_item in security_baseline[:3]:
                content = knowledge_item.get('content', '')
                context_parts.append(f"- {content}")
        
        return '\n'.join(context_parts)
    
    def analyze_with_openai(self, query: str, context: str) -> str:
        """Analyze using OpenAI GPT-4 directly"""
        
        system_prompt = """You are an expert cybersecurity analyst specializing in web application security. 
        You analyze HTTP traffic data to identify vulnerabilities and provide detailed security assessments.
        
        Provide comprehensive analysis including:
        1. Clear vulnerability identification
        2. Risk severity (Critical/High/Medium/Low) 
        3. Detailed explanation of security issues
        4. Specific remediation recommendations
        5. Best practices to prevent similar issues
        
        Be thorough, accurate, and professional."""
        
        user_prompt = f"""
SECURITY ANALYSIS REQUEST:
{query}

AVAILABLE SECURITY DATA:
{context}

Please analyze this security data and provide a comprehensive security assessment with:
- Vulnerability identification and risk ratings
- Impact analysis and threat assessment  
- Specific remediation steps and recommendations
- Best practices for preventing similar issues
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=2000,
                temperature=0.1
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"❌ OpenAI analysis failed: {e}")
            return f"Analysis failed due to error: {e}"
    
    def analyze_security_query(self, query: str) -> str:
        """Main method for security analysis using OpenAI + RAG"""
        print(f"🔍 Analyzing with GPT-4: {query}")
        
        # Retrieve knowledge using RAG
        print("📚 Retrieving security knowledge...")
        knowledge = self.query_security_knowledge(query, n_results=15)
        
        if not knowledge:
            return "⚠️ No security data found. Please run the collector first."
        
        # Prepare context
        print("🤖 Preparing analysis context...")
        context = self.prepare_security_context(knowledge)
        
        # Analyze with GPT-4
        print("🔬 Running GPT-4 security analysis...")
        analysis_result = self.analyze_with_openai(query, context)
        
        # Format final result
        final_result = f"""
🔒 AI-POWERED SECURITY ANALYSIS REPORT
{'='*60}
📋 Query: {query}
📊 Knowledge Sources: {len(knowledge)} documents analyzed
🤖 AI Model: OpenAI GPT-4

{analysis_result}

{'='*60}
🔬 Analysis powered by: OWASP ZAP + OpenAI GPT-4 + RAG
        """
        
        return final_result
    
    def get_comprehensive_security_summary(self) -> str:
        """Get comprehensive security summary"""
        query = "Provide a comprehensive security analysis of all HTTP traffic, identifying vulnerabilities, risks, and recommendations"
        return self.analyze_security_query(query)
    
    def analyze_critical_vulnerabilities(self) -> str:
        """Analyze critical vulnerabilities"""
        query = "Identify and analyze critical security vulnerabilities like SQL injection, XSS, and sensitive data exposure"
        return self.analyze_security_query(query)
    
    def assess_authentication_security(self) -> str:
        """Assess authentication security"""
        query = "Analyze authentication mechanisms, password security, token handling, and authorization controls"
        return self.analyze_security_query(query)
    
    def evaluate_data_protection(self) -> str:
        """Evaluate data protection"""
        query = "Evaluate data protection measures, sensitive data exposure, encryption usage, and privacy compliance"
        return self.analyze_security_query(query)

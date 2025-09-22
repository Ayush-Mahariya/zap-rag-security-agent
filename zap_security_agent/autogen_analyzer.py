"""Enhanced Security Analyzer with AutoGen and OpenAI Integration"""
import os
import chromadb
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any
import autogen
from autogen import AssistantAgent, UserProxyAgent, config_list_from_json, config_list_from_models

class AutoGenSecurityAnalyzer:
    def __init__(self):
        print("🔧 Initializing AutoGen Security Analyzer...")
        
        # Setup OpenAI configuration
        self.setup_openai_config()
        
        # Connect to ChromaDB
        self.chroma_client = chromadb.Client()
        
        try:
            self.collection = self.chroma_client.get_collection("security_knowledge")
            print("✅ Connected to security knowledge base")
        except Exception as e:
            print(f"❌ Failed to connect to ChromaDB: {e}")
            print("💡 Run the collector first to create the knowledge base")
            raise
        
        # Load embedding model
        print("🤖 Loading embedding model...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Setup AutoGen agents
        self.setup_autogen_agents()
        
        print("✅ AutoGen Security Analyzer ready!")
    
    def setup_openai_config(self):
        """Setup OpenAI configuration for AutoGen"""
        # Get API key from environment
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise Exception("OPENAI_API_KEY environment variable not set!")
        
        # AutoGen configuration
        self.config_list = [
            {
                "model": "gpt-4",
                "api_key": api_key,
                "api_type": "openai",
                "api_base": "https://api.openai.com/v1"
            },
            {
                "model": "gpt-3.5-turbo",
                "api_key": api_key,
                "api_type": "openai", 
                "api_base": "https://api.openai.com/v1"
            }
        ]
        
        print("✅ OpenAI configuration ready")
    
    def setup_autogen_agents(self):
        """Setup AutoGen agents for security analysis"""
        
        # Security Expert Agent
        self.security_expert = AssistantAgent(
            name="SecurityExpert",
            system_message="""You are an expert cybersecurity analyst specializing in web application security. 
            Your role is to analyze HTTP traffic, identify vulnerabilities, and provide detailed security assessments.
            
            Key responsibilities:
            - Analyze HTTP requests and responses for security vulnerabilities
            - Identify SQL injection, XSS, authentication issues, data exposure
            - Provide risk assessments and severity ratings
            - Suggest specific remediation steps
            - Explain security concepts clearly and thoroughly
            
            Always provide:
            1. Clear vulnerability identification
            2. Risk severity (Critical/High/Medium/Low)
            3. Detailed explanation of the security issue
            4. Specific remediation recommendations
            5. Best practices to prevent similar issues
            
            Be thorough, accurate, and professional in your analysis.""",
            llm_config={"config_list": self.config_list, "temperature": 0.1}
        )
        
        # RAG Research Agent
        self.rag_researcher = AssistantAgent(
            name="RAGResearcher", 
            system_message="""You are a specialized research assistant that analyzes security knowledge and HTTP traffic data.
            Your role is to search through collected security data and provide relevant context for analysis.
            
            Key responsibilities:
            - Analyze retrieved security knowledge from the vector database
            - Identify patterns and trends in HTTP traffic data
            - Correlate findings across multiple data sources
            - Provide statistical analysis of security issues
            - Extract actionable insights from complex datasets
            
            Focus on:
            - Data-driven security insights
            - Pattern recognition in attack vectors
            - Statistical correlation of vulnerabilities
            - Evidence-based security recommendations""",
            llm_config={"config_list": self.config_list, "temperature": 0.1}
        )
        
        # User Proxy for orchestration
        self.user_proxy = UserProxyAgent(
            name="SecurityAnalysisOrchestrator",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=3,
            code_execution_config=False,
            system_message="You coordinate security analysis between experts and researchers."
        )
        
        print("✅ AutoGen agents configured")
    
    def query_security_knowledge(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Query the security knowledge base using semantic search"""
        try:
            # Create query embedding
            query_embedding = self.embedding_model.encode([query])[0]
            
            # Search ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )
            
            # Format results
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
        """Prepare security context for AutoGen analysis"""
        
        # Categorize findings
        http_requests = []
        security_baseline = []
        security_issues = {}
        
        for item in knowledge:
            metadata = item.get('metadata', {})
            
            if metadata.get('type') == 'http_request':
                http_requests.append(item)
                
                # Extract security issues
                issues = metadata.get('security_issues', '').split(',')
                for issue in issues:
                    issue = issue.strip()
                    if issue and issue != 'none':
                        security_issues[issue] = security_issues.get(issue, 0) + 1
                        
            elif metadata.get('type') == 'security_knowledge':
                security_baseline.append(item)
        
        # Build context string
        context_parts = []
        
        # Traffic summary
        context_parts.append(f"=== HTTP TRAFFIC ANALYSIS DATA ===")
        context_parts.append(f"Total HTTP requests analyzed: {len(http_requests)}")
        
        if security_issues:
            context_parts.append(f"\nSecurity Issues Detected:")
            for issue, count in security_issues.items():
                context_parts.append(f"- {issue.replace('_', ' ').title()}: {count} instances")
        
        # Sample requests
        context_parts.append(f"\nSample HTTP Requests:")
        for i, req in enumerate(http_requests[:5], 1):
            metadata = req.get('metadata', {})
            method = metadata.get('method', 'UNKNOWN')
            url = metadata.get('url', 'UNKNOWN')
            issues = metadata.get('security_issues', 'none')
            context_parts.append(f"{i}. {method} {url}")
            if issues != 'none':
                context_parts.append(f"   Security flags: {issues}")
        
        # Security knowledge
        if security_baseline:
            context_parts.append(f"\n=== RELEVANT SECURITY KNOWLEDGE ===")
            for knowledge_item in security_baseline[:3]:
                content = knowledge_item.get('content', '')
                context_parts.append(f"- {content}")
        
        return '\n'.join(context_parts)
    
    def analyze_with_autogen(self, query: str, context: str) -> str:
        """Perform security analysis using AutoGen agents"""
        
        # Create analysis prompt
        analysis_prompt = f"""
SECURITY ANALYSIS REQUEST:
Query: {query}

AVAILABLE DATA:
{context}

ANALYSIS REQUIREMENTS:
1. Identify all security vulnerabilities and issues
2. Assess risk severity for each issue (Critical/High/Medium/Low)
3. Explain the potential impact of each vulnerability
4. Provide specific, actionable remediation steps
5. Suggest preventive measures and best practices

Please provide a comprehensive security analysis based on the available data.
        """
        
        try:
            # Initiate conversation between agents
            chat_result = self.user_proxy.initiate_chat(
                self.security_expert,
                message=analysis_prompt,
                max_turns=2
            )
            
            # Extract the analysis result
            if hasattr(chat_result, 'chat_history') and chat_result.chat_history:
                # Get the last response from security expert
                for message in reversed(chat_result.chat_history):
                    if message.get('name') == 'SecurityExpert':
                        return message.get('content', 'No analysis provided')
            
            # Fallback: return summary
            return "Analysis completed - please check the conversation history"
            
        except Exception as e:
            print(f"❌ AutoGen analysis failed: {e}")
            return f"Analysis failed due to error: {e}"
    
    def analyze_security_query(self, query: str) -> str:
        """Main method to analyze security queries using AutoGen + RAG"""
        print(f"🔍 Analyzing with AutoGen: {query}")
        
        # Step 1: Retrieve relevant knowledge using RAG
        print("📚 Retrieving security knowledge...")
        knowledge = self.query_security_knowledge(query, n_results=15)
        
        if not knowledge:
            return "⚠️ No security data found. Please run the collector first to gather traffic data."
        
        # Step 2: Prepare context for AutoGen
        print("🤖 Preparing analysis context...")
        context = self.prepare_security_context(knowledge)
        
        # Step 3: Analyze with AutoGen agents
        print("🔬 Running AutoGen security analysis...")
        analysis_result = self.analyze_with_autogen(query, context)
        
        # Step 4: Format final result
        final_result = f"""
🔒 AI-POWERED SECURITY ANALYSIS REPORT
{'='*60}
📋 Query: {query}
📊 Knowledge Sources: {len(knowledge)} documents analyzed
🤖 AI Model: GPT-4 via AutoGen

{analysis_result}

{'='*60}
🔬 Analysis powered by: OWASP ZAP + AutoGen + OpenAI GPT-4 + RAG
        """
        
        return final_result
    
    # Predefined analysis methods
    def get_comprehensive_security_summary(self) -> str:
        """Get AI-powered comprehensive security summary"""
        query = "Provide a comprehensive security analysis of all HTTP traffic, identifying vulnerabilities, risks, and recommendations"
        return self.analyze_security_query(query)
    
    def analyze_critical_vulnerabilities(self) -> str:
        """Analyze critical security vulnerabilities"""
        query = "Identify and analyze critical security vulnerabilities like SQL injection, XSS, and sensitive data exposure"
        return self.analyze_security_query(query)
    
    def assess_authentication_security(self) -> str:
        """Assess authentication and authorization security"""
        query = "Analyze authentication mechanisms, password security, token handling, and authorization controls"
        return self.analyze_security_query(query)
    
    def evaluate_data_protection(self) -> str:
        """Evaluate data protection and privacy"""
        query = "Evaluate data protection measures, sensitive data exposure, encryption usage, and privacy compliance"
        return self.analyze_security_query(query)

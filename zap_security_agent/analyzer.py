"""RAG-based Security Analysis Engine"""
import chromadb
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any

class SecurityAnalyzer:
    def __init__(self):
        print("🔧 Initializing Security Analyzer...")
        
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
        print("✅ Security Analyzer ready!")
    
    def query_security_knowledge(self, query: str, n_results: int = 8) -> List[Dict[str, Any]]:
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
    
    def analyze_security_query(self, query: str) -> str:
        """Perform comprehensive security analysis using RAG"""
        print(f"🔍 Analyzing: {query}")
        
        # Retrieve relevant knowledge
        knowledge = self.query_security_knowledge(query, n_results=10)
        
        if not knowledge:
            return "⚠️ No security data found. Please run the collector first to gather traffic data."
        
        # Generate comprehensive analysis
        return self._generate_security_report(query, knowledge)
    
    def _generate_security_report(self, query: str, knowledge: List[Dict[str, Any]]) -> str:
        """Generate detailed security analysis report"""
        
        # Categorize findings
        http_requests = []
        security_baseline = []
        security_issues = {}
        request_methods = {}
        
        for item in knowledge:
            metadata = item.get('metadata', {})
            content = item.get('content', '')
            
            # Categorize by type
            if metadata.get('type') == 'http_request':
                http_requests.append(item)
                
                # Count methods
                method = metadata.get('method', 'UNKNOWN')
                request_methods[method] = request_methods.get(method, 0) + 1
                
                # Count security issues
                issues = metadata.get('security_issues', '').split(',')
                for issue in issues:
                    issue = issue.strip()
                    if issue and issue != 'none':
                        security_issues[issue] = security_issues.get(issue, 0) + 1
                        
            elif metadata.get('type') == 'security_knowledge':
                security_baseline.append(item)
        
        # Build comprehensive report
        report_lines = []
        report_lines.append("🔒 SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"📋 Query: {query}")
        report_lines.append(f"📊 Knowledge sources analyzed: {len(knowledge)}")
        
        # Executive Summary
        report_lines.append(f"\n📈 EXECUTIVE SUMMARY")
        report_lines.append("-" * 30)
        report_lines.append(f"• HTTP requests analyzed: {len(http_requests)}")
        report_lines.append(f"• Security issues identified: {len(security_issues)}")
        report_lines.append(f"• Security knowledge consulted: {len(security_baseline)}")
        
        # HTTP Traffic Analysis
        if http_requests:
            report_lines.append(f"\n🌐 HTTP TRAFFIC ANALYSIS")
            report_lines.append("-" * 35)
            
            if request_methods:
                report_lines.append(f"📊 HTTP Methods:")
                for method, count in sorted(request_methods.items()):
                    report_lines.append(f"   • {method}: {count} requests")
            
            # Show sample requests
            report_lines.append(f"\n🔍 Sample Request Analysis:")
            for i, req in enumerate(http_requests[:3], 1):
                metadata = req.get('metadata', {})
                method = metadata.get('method', 'UNKNOWN')
                url = metadata.get('url', 'UNKNOWN')
                issues = metadata.get('security_issues', 'none')
                report_lines.append(f"   {i}. {method} {url[:50]}{'...' if len(url) > 50 else ''}")
                if issues != 'none':
                    report_lines.append(f"      Security flags: {issues}")
        
        # Security Issues Analysis
        if security_issues:
            report_lines.append(f"\n⚠️  SECURITY ISSUES DETECTED")
            report_lines.append("-" * 40)
            
            for issue, count in sorted(security_issues.items(), key=lambda x: x[1], reverse=True):
                severity = self._assess_severity(issue)
                issue_name = issue.replace('_', ' ').title()
                report_lines.append(f"• {issue_name}: {count} instances [{severity} SEVERITY]")
        
        # Security Recommendations
        report_lines.append(f"\n✅ SECURITY RECOMMENDATIONS")
        report_lines.append("-" * 40)
        
        recommendations = self._generate_recommendations(security_issues)
        for rec in recommendations:
            report_lines.append(f"• {rec}")
        
        # Risk Assessment
        risk_level = self._assess_overall_risk(security_issues)
        report_lines.append(f"\n🎯 RISK ASSESSMENT")
        report_lines.append("-" * 25)
        report_lines.append(f"Overall Risk Level: {risk_level}")
        report_lines.append(f"Priority Actions: {self._get_priority_actions(security_issues)}")
        
        # Related Security Knowledge
        if security_baseline:
            report_lines.append(f"\n📚 RELEVANT SECURITY KNOWLEDGE")
            report_lines.append("-" * 45)
            
            for knowledge_item in security_baseline[:2]:
                content = knowledge_item.get('content', '')
                report_lines.append(f"• {content[:100]}{'...' if len(content) > 100 else ''}")
        
        report_lines.append("=" * 70)
        
        return '\n'.join(report_lines)
    
    def _assess_severity(self, issue: str) -> str:
        """Assess severity level of security issue"""
        critical = ['potential_sql_injection']
        high = ['contains_password', 'potential_xss', 'contains_sensitive_data']
        medium = ['unencrypted_request', 'state_changing_request']
        
        if issue in critical:
            return "CRITICAL"
        elif issue in high:
            return "HIGH"
        elif issue in medium:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_overall_risk(self, issues: Dict[str, int]) -> str:
        """Assess overall risk level"""
        if not issues:
            return "LOW - No significant issues detected"
        
        critical_count = sum(count for issue, count in issues.items() 
                           if self._assess_severity(issue) == "CRITICAL")
        high_count = sum(count for issue, count in issues.items() 
                        if self._assess_severity(issue) == "HIGH")
        
        if critical_count > 0:
            return "CRITICAL - Immediate action required"
        elif high_count >= 3:
            return "HIGH - Significant security concerns"
        elif high_count > 0:
            return "MEDIUM - Some security issues detected"
        else:
            return "LOW - Minor issues only"
    
    def _get_priority_actions(self, issues: Dict[str, int]) -> str:
        """Get priority actions based on issues"""
        if not issues:
            return "Continue security monitoring"
        
        actions = []
        if 'potential_sql_injection' in issues:
            actions.append("Fix SQL injection vulnerabilities")
        if 'contains_password' in issues:
            actions.append("Secure password transmission")
        if 'unencrypted_request' in issues:
            actions.append("Enforce HTTPS")
        if 'potential_xss' in issues:
            actions.append("Implement input sanitization")
        
        return actions[0] if actions else "Review security configuration"
    
    def _generate_recommendations(self, issues: Dict[str, int]) -> List[str]:
        """Generate specific security recommendations"""
        recommendations = []
        
        if 'contains_password' in issues:
            recommendations.append("Implement secure authentication: Use HTTPS and avoid passwords in URLs")
        
        if 'contains_sensitive_data' in issues:
            recommendations.append("Protect sensitive data: Use encryption and secure storage for API keys/tokens")
        
        if 'potential_sql_injection' in issues:
            recommendations.append("Prevent SQL injection: Use parameterized queries and input validation")
        
        if 'potential_xss' in issues:
            recommendations.append("Prevent XSS attacks: Sanitize inputs and encode outputs properly")
        
        if 'unencrypted_request' in issues:
            recommendations.append("Enforce encryption: Require HTTPS for all sensitive communications")
        
        if 'state_changing_request' in issues:
            recommendations.append("CSRF protection: Implement anti-CSRF tokens for state-changing operations")
        
        # Default recommendations
        if not recommendations:
            recommendations = [
                "Implement regular security audits and vulnerability scanning",
                "Establish comprehensive input validation on all user inputs",
                "Use secure session management and authentication practices",
                "Keep all software components and dependencies up to date",
                "Monitor and log security-related events for analysis"
            ]
        
        return recommendations[:6]  # Return top 6 recommendations
    
    # Predefined analysis methods
    def get_security_summary(self) -> str:
        """Get comprehensive security summary"""
        query = "security vulnerabilities HTTP requests analysis threats risks authentication encryption"
        return self.analyze_security_query(query)
    
    def check_sensitive_data_exposure(self) -> str:
        """Check for sensitive data exposure"""
        query = "passwords API keys tokens credentials sensitive authentication data exposure"
        return self.analyze_security_query(query)
    
    def analyze_authentication_security(self) -> str:
        """Analyze authentication security"""
        query = "authentication login password token session security credentials authorization"
        return self.analyze_security_query(query)
    
    def check_encryption_usage(self) -> str:
        """Check encryption and HTTPS usage"""
        query = "HTTPS HTTP encryption SSL TLS secure communication unencrypted requests"
        return self.analyze_security_query(query)
    
    def get_system_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        try:
            total_count = self.collection.count()
            
            if total_count > 0:
                # Get sample of documents to analyze types
                sample_size = min(20, total_count)
                sample = self.collection.get(limit=sample_size, include=['metadatas'])
                
                doc_types = {}
                methods = {}
                issues = {}
                
                for metadata in sample['metadatas']:
                    # Count document types
                    doc_type = metadata.get('type', 'unknown')
                    doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
                    
                    # Count HTTP methods
                    if doc_type == 'http_request':
                        method = metadata.get('method', 'UNKNOWN')
                        methods[method] = methods.get(method, 0) + 1
                        
                        # Count security issues
                        request_issues = metadata.get('security_issues', '').split(',')
                        for issue in request_issues:
                            issue = issue.strip()
                            if issue and issue != 'none':
                                issues[issue] = issues.get(issue, 0) + 1
                
                return {
                    'total_documents': total_count,
                    'document_types': doc_types,
                    'http_methods': methods,
                    'security_issues': issues,
                    'sample_size': sample_size
                }
            else:
                return {
                    'total_documents': 0,
                    'message': 'No data available. Run the collector first.'
                }
                
        except Exception as e:
            return {
                'error': f"Statistics error: {e}",
                'total_documents': 0
            }

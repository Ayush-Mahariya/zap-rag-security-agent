"""Main Security Analysis Application Interface"""
import sys
from analyzer import SecurityAnalyzer

class SecurityAnalysisApp:
    def __init__(self):
        print("🔒 ZAP-AutoGen-RAG Security Analysis System")
        print("=" * 55)
        
        try:
            self.analyzer = SecurityAnalyzer()
            print("✅ System initialized successfully!")
        except Exception as e:
            print(f"❌ System initialization failed: {e}")
            print("\n💡 Troubleshooting Steps:")
            print("   1. Run the collector first: poetry run python zap_security_agent/collector.py")
            print("   2. Ensure ZAP daemon is running")
            print("   3. Let collector process some traffic data")
            sys.exit(1)
    
    def show_welcome_banner(self):
        """Display welcome banner"""
        banner = """
╔════════════════════════════════════════════════════════════════╗
║                    🔒 SECURITY ANALYSIS SYSTEM                 ║
║              Advanced AI-Powered Web Security Analysis          ║
║                                                               ║
║  🎯 Analyzes HTTP traffic for security vulnerabilities        ║
║  🤖 Uses AI and knowledge retrieval for intelligent insights  ║
║  📊 Provides actionable security recommendations              ║
╚════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_main_menu(self):
        """Display main menu options"""
        print("\n📋 SECURITY ANALYSIS OPTIONS")
        print("═" * 50)
        print("1. 🔍 Custom Security Query")
        print("2. 📊 Comprehensive Security Summary") 
        print("3. ⚠️  Sensitive Data Exposure Check")
        print("4. 🔐 Authentication Security Analysis")
        print("5. 🛡️  Encryption & HTTPS Analysis")
        print("6. 📈 System Knowledge Statistics")
        print("7. 📚 Example Security Queries")
        print("8. ❌ Exit System")
        print("═" * 50)
    
    def show_example_queries(self):
        """Display example security queries"""
        examples = [
            "What are the most common HTTP methods used in the captured traffic?",
            "Are there any requests containing passwords or sensitive authentication data?",
            "Find HTTP requests that might be vulnerable to SQL injection attacks",
            "What authentication mechanisms and security tokens are being used?",
            "Are there any potential cross-site scripting (XSS) vulnerabilities?",
            "Check for missing security headers in HTTP responses",
            "Find POST requests that might be vulnerable to CSRF attacks",
            "Are there any suspicious or unusual user agents in the traffic?",
            "What sensitive API keys or tokens are exposed in request parameters?",
            "Analyze login endpoints and authentication flows for security issues",
            "Check for unencrypted HTTP requests that should use HTTPS",
            "What are the main security risks identified in the traffic analysis?"
        ]
        
        print("\n📚 EXAMPLE SECURITY QUERIES")
        print("═" * 60)
        print("💡 Use these examples as inspiration for your own security analysis:")
        print()
        
        for i, example in enumerate(examples, 1):
            print(f"{i:2d}. {example}")
        
        print("═" * 60)
        print("✨ Try asking these questions in 'Custom Security Query' option!")
    
    def handle_custom_query(self):
        """Handle user's custom security query"""
        print("\n🔍 CUSTOM SECURITY QUERY")
        print("─" * 35)
        print("💡 Ask any security-related question about the analyzed traffic.")
        print("   Examples: 'Find password vulnerabilities', 'Check for XSS issues'")
        print()
        
        query = input("🤖 Enter your security question: ").strip()
        
        if not query:
            print("❌ Please enter a valid query")
            return
        
        if len(query) < 3:
            print("❌ Query too short. Please provide more details.")
            return
        
        print(f"\n🤖 Analyzing: '{query}'")
        print("⏳ Processing security analysis...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_security_query(query)
            print(response)
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
    
    def handle_security_summary(self):
        """Generate comprehensive security summary"""
        print("\n📊 COMPREHENSIVE SECURITY SUMMARY")
        print("─" * 45)
        print("🤖 Generating complete security analysis of all captured traffic...")
        print("⏳ This may take a moment...")
        print("─" * 60)
        
        try:
            response = self.analyzer.get_security_summary()
            print(response)
        except Exception as e:
            print(f"❌ Summary generation failed: {e}")
    
    def handle_sensitive_data_check(self):
        """Check for sensitive data exposure"""
        print("\n⚠️  SENSITIVE DATA EXPOSURE ANALYSIS")
        print("─" * 45)
        print("🤖 Scanning for passwords, API keys, tokens, and credentials...")
        print("⏳ Analyzing traffic for data exposure risks...")
        print("─" * 60)
        
        try:
            response = self.analyzer.check_sensitive_data_exposure()
            print(response)
        except Exception as e:
            print(f"❌ Sensitive data check failed: {e}")
    
    def handle_authentication_analysis(self):
        """Analyze authentication security"""
        print("\n🔐 AUTHENTICATION SECURITY ANALYSIS")
        print("─" * 45)
        print("🤖 Analyzing authentication mechanisms and login security...")
        print("⏳ Reviewing authentication flows and credential handling...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_authentication_security()
            print(response)
        except Exception as e:
            print(f"❌ Authentication analysis failed: {e}")
    
    def handle_encryption_analysis(self):
        """Analyze encryption and HTTPS usage"""
        print("\n🛡️  ENCRYPTION & HTTPS ANALYSIS")
        print("─" * 40)
        print("🤖 Analyzing communication encryption and secure protocols...")
        print("⏳ Checking HTTPS usage and identifying unencrypted requests...")
        print("─" * 60)
        
        try:
            response = self.analyzer.check_encryption_usage()
            print(response)
        except Exception as e:
            print(f"❌ Encryption analysis failed: {e}")
    
    def show_system_statistics(self):
        """Display system statistics"""
        print("\n📈 SYSTEM KNOWLEDGE STATISTICS")
        print("─" * 40)
        
        try:
            stats = self.analyzer.get_system_statistics()
            
            if 'error' in stats:
                print(f"❌ {stats['error']}")
                return
            
            print(f"📊 Total documents in knowledge base: {stats['total_documents']}")
            
            if stats['total_documents'] == 0:
                print("⚠️  No data available. Run the collector first.")
                return
            
            print(f"📋 Analysis based on {stats.get('sample_size', 0)} documents")
            
            # Document types
            if 'document_types' in stats and stats['document_types']:
                print(f"\n📄 Document Types:")
                for doc_type, count in stats['document_types'].items():
                    type_name = doc_type.replace('_', ' ').title()
                    print(f"   • {type_name}: {count}")
            
            # HTTP methods
            if 'http_methods' in stats and stats['http_methods']:
                print(f"\n🌐 HTTP Methods:")
                for method, count in stats['http_methods'].items():
                    print(f"   • {method}: {count}")
            
            # Security issues
            if 'security_issues' in stats and stats['security_issues']:
                print(f"\n⚠️  Security Issues Detected:")
                for issue, count in stats['security_issues'].items():
                    issue_name = issue.replace('_', ' ').title()
                    print(f"   • {issue_name}: {count}")
            else:
                print(f"\n✅ No major security issues detected in sample")
            
            print("\n💡 Use other menu options for detailed security analysis")
            
        except Exception as e:
            print(f"❌ Statistics error: {e}")
    
    def run(self):
        """Main application loop"""
        self.show_welcome_banner()
        
        print("\n🚀 Welcome to the AI-Powered Security Analysis System!")
        print("\n💡 System Requirements:")
        print("   ✅ ZAP daemon running (localhost:8080)")
        print("   ✅ Traffic data collected via collector")
        print("   ✅ Security knowledge base populated")
        print("\n🎯 This system analyzes HTTP traffic for security vulnerabilities")
        print("   and provides intelligent insights using AI and knowledge retrieval.")
        
        while True:
            try:
                self.show_main_menu()
                
                choice = input("\n🎯 Select option (1-8): ").strip()
                
                if choice == '1':
                    self.handle_custom_query()
                elif choice == '2':
                    self.handle_security_summary()
                elif choice == '3':
                    self.handle_sensitive_data_check()
                elif choice == '4':
                    self.handle_authentication_analysis()
                elif choice == '5':
                    self.handle_encryption_analysis()
                elif choice == '6':
                    self.show_system_statistics()
                elif choice == '7':
                    self.show_example_queries()
                elif choice == '8':
                    print("\n👋 Thank you for using ZAP-AutoGen-RAG Security Analyzer!")
                    print("🔒 Keep your applications secure!")
                    print("💡 Remember to regularly analyze your web traffic for security issues.")
                    break
                else:
                    print("❌ Invalid option. Please select 1-8.")
                
                # Pause after analysis operations
                if choice in ['1', '2', '3', '4', '5']:
                    print("\n" + "─" * 60)
                    input("⏎  Press Enter to return to main menu...")
                elif choice == '6':
                    input("\n⏎  Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\n👋 System interrupted. Goodbye!")
                print("🔒 Stay secure!")
                break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                print("💡 Please try again or restart the system.")
                input("\n⏎  Press Enter to continue...")

def main():
    """Application entry point"""
    try:
        app = SecurityAnalysisApp()
        app.run()
    except Exception as e:
        print(f"\n❌ Fatal system error: {e}")
        print("\n💡 Troubleshooting:")
        print("   • Ensure ZAP daemon is running")
        print("   • Run collector first to gather data")
        print("   • Check system dependencies")
        sys.exit(1)

if __name__ == "__main__":
    main()

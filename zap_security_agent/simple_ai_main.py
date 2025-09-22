"""Simplified AI-Powered Security Analysis Application"""
import sys
import os
from openai_analyzer import OpenAISecurityAnalyzer

class SimpleAISecurityApp:
    def __init__(self):
        print("🔒 ZAP-RAG Security Analysis System")
        print("🤖 Powered by OpenAI GPT-4")
        print("=" * 55)
        
        # Check OpenAI API key
        if not os.getenv("OPENAI_API_KEY"):
            print("❌ OpenAI API key not found!")
            print("\n💡 Set your API key:")
            print("export OPENAI_API_KEY='your-api-key-here'")
            sys.exit(1)
        
        try:
            self.analyzer = OpenAISecurityAnalyzer()
            print("✅ AI-powered system ready!")
        except Exception as e:
            print(f"❌ System initialization failed: {e}")
            print("\n💡 Troubleshooting:")
            print("   1. Run the collector first")
            print("   2. Check OpenAI API key")
            sys.exit(1)
    
    def show_ai_banner(self):
        banner = """
╔════════════════════════════════════════════════════════════╗
║            🤖 GPT-4 POWERED SECURITY ANALYSIS              ║
║                                                           ║
║  🔒 OWASP ZAP Traffic Capture                             ║
║  🧠 OpenAI GPT-4 Intelligence                             ║
║  📊 RAG Knowledge Retrieval                               ║
║  🎯 Advanced Vulnerability Detection                      ║
╚════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_menu(self):
        print("\n🤖 GPT-4 POWERED SECURITY ANALYSIS")
        print("═" * 50)
        print("1. 🧠 AI Comprehensive Security Analysis")
        print("2. ⚡ AI Critical Vulnerability Assessment")
        print("3. 🔐 AI Authentication Security Review")
        print("4. 🛡️  AI Data Protection Evaluation")
        print("5. 🔍 Custom AI Security Query")
        print("6. ❌ Exit System")
        print("═" * 50)
    
    def handle_ai_comprehensive(self):
        print("\n🧠 AI COMPREHENSIVE SECURITY ANALYSIS")
        print("─" * 45)
        print("🤖 GPT-4 analyzing all security aspects...")
        print("⏳ Advanced analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.get_comprehensive_security_summary()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_ai_critical(self):
        print("\n⚡ AI CRITICAL VULNERABILITY ASSESSMENT")
        print("─" * 45)
        print("🤖 GPT-4 analyzing critical vulnerabilities...")
        print("⏳ Threat analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_critical_vulnerabilities()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_ai_auth(self):
        print("\n🔐 AI AUTHENTICATION SECURITY REVIEW")
        print("─" * 40)
        print("🤖 GPT-4 analyzing authentication...")
        print("⏳ Authentication review in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.assess_authentication_security()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_ai_data_protection(self):
        print("\n🛡️  AI DATA PROTECTION EVALUATION")
        print("─" * 35)
        print("🤖 GPT-4 evaluating data protection...")
        print("⏳ Data security assessment in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.evaluate_data_protection()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_custom_query(self):
        print("\n🔍 CUSTOM AI SECURITY QUERY")
        print("─" * 30)
        print("🤖 Ask GPT-4 any security question!")
        print()
        
        query = input("🧠 Ask GPT-4: ").strip()
        
        if not query:
            print("❌ Please enter a valid query")
            return
        
        print(f"\n🤖 GPT-4 analyzing: '{query}'")
        print("⏳ AI analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_security_query(query)
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def run(self):
        self.show_ai_banner()
        
        print("\n🚀 Welcome to GPT-4 Powered Security Analysis!")
        print("\n✨ This system uses OpenAI GPT-4 for advanced security insights")
        print("   combined with OWASP ZAP traffic analysis and RAG knowledge retrieval.")
        
        while True:
            try:
                self.show_menu()
                choice = input("\n🎯 Select option (1-6): ").strip()
                
                if choice == '1':
                    self.handle_ai_comprehensive()
                elif choice == '2':
                    self.handle_ai_critical()
                elif choice == '3':
                    self.handle_ai_auth()
                elif choice == '4':
                    self.handle_ai_data_protection()
                elif choice == '5':
                    self.handle_custom_query()
                elif choice == '6':
                    print("\n🤖 Thank you for using GPT-4 Security Analysis!")
                    print("🔒 Keep your applications secure with AI insights!")
                    break
                else:
                    print("❌ Invalid option. Please select 1-6.")
                
                if choice in ['1', '2', '3', '4', '5']:
                    print("\n" + "─" * 60)
                    input("⏎  Press Enter to return to main menu...")
                    
            except KeyboardInterrupt:
                print("\n\n👋 AI System interrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ System error: {e}")
                input("\n⏎  Press Enter to continue...")

def main():
    try:
        app = SimpleAISecurityApp()
        app.run()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

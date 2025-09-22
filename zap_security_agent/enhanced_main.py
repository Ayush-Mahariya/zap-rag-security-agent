"""Enhanced Main Application with AutoGen + OpenAI Integration"""
import sys
import os
from autogen_analyzer import AutoGenSecurityAnalyzer

class EnhancedSecurityApp:
    def __init__(self):
        print("🔒 ZAP-AutoGen-RAG Security Analysis System")
        print("🤖 Enhanced with OpenAI GPT-4 + AutoGen")
        print("=" * 65)
        
        # Check OpenAI API key
        if not os.getenv("OPENAI_API_KEY"):
            print("❌ OpenAI API key not found!")
            print("\n💡 Set your API key:")
            print("export OPENAI_API_KEY='your-api-key-here'")
            sys.exit(1)
        
        try:
            self.analyzer = AutoGenSecurityAnalyzer()
            print("✅ AI-powered system ready!")
        except Exception as e:
            print(f"❌ System initialization failed: {e}")
            print("\n💡 Troubleshooting:")
            print("   1. Run the collector first to gather data")
            print("   2. Ensure ZAP daemon is running") 
            print("   3. Check OpenAI API key is valid")
            sys.exit(1)
    
    def show_ai_banner(self):
        """Display AI-powered banner"""
        banner = """
╔════════════════════════════════════════════════════════════════╗
║              🤖 AI-POWERED SECURITY ANALYSIS SYSTEM            ║
║                                                               ║
║  🔒 OWASP ZAP Traffic Capture                                 ║
║  🤖 AutoGen Multi-Agent AI Analysis                           ║
║  🧠 OpenAI GPT-4 Intelligence                                 ║
║  📊 RAG Knowledge Retrieval                                   ║
║  🎯 Advanced Vulnerability Detection                          ║
╚════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_enhanced_menu(self):
        """Display enhanced menu with AI options"""
        print("\n🤖 AI-POWERED SECURITY ANALYSIS")
        print("═" * 55)
        print("🔥 PREMIUM AI ANALYSIS (GPT-4 Powered)")
        print("1. 🧠 AI Comprehensive Security Analysis")
        print("2. ⚡ AI Critical Vulnerability Assessment") 
        print("3. 🔐 AI Authentication Security Review")
        print("4. 🛡️  AI Data Protection Evaluation")
        print("5. 🔍 Custom AI Security Query")
        print("\n📊 STANDARD ANALYSIS")
        print("6. 📈 System Knowledge Statistics")
        print("7. 📚 Example Security Queries") 
        print("8. ❌ Exit System")
        print("═" * 55)
        print("💡 AI Analysis uses GPT-4 for advanced insights!")
    
    def handle_ai_comprehensive_analysis(self):
        """Handle AI-powered comprehensive analysis"""
        print("\n🧠 AI COMPREHENSIVE SECURITY ANALYSIS")
        print("─" * 50)
        print("🤖 Launching GPT-4 powered multi-agent analysis...")
        print("🔬 Analyzing all security aspects of captured traffic...")
        print("⏳ This advanced analysis may take 30-60 seconds...")
        print("─" * 60)
        
        try:
            response = self.analyzer.get_comprehensive_security_summary()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
            print("💡 Check OpenAI API key and internet connection")
    
    def handle_ai_critical_vulnerabilities(self):
        """Handle AI-powered critical vulnerability assessment"""
        print("\n⚡ AI CRITICAL VULNERABILITY ASSESSMENT")
        print("─" * 50)
        print("🤖 GPT-4 analyzing critical security vulnerabilities...")
        print("🔍 Focusing on high-impact security issues...")
        print("⏳ Advanced threat analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_critical_vulnerabilities()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_ai_authentication_review(self):
        """Handle AI-powered authentication security review"""
        print("\n🔐 AI AUTHENTICATION SECURITY REVIEW")
        print("─" * 45)
        print("🤖 GPT-4 analyzing authentication mechanisms...")
        print("�� Reviewing login security and access controls...")
        print("⏳ Authentication analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.assess_authentication_security()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_ai_data_protection(self):
        """Handle AI-powered data protection evaluation"""
        print("\n🛡️  AI DATA PROTECTION EVALUATION")
        print("─" * 40)
        print("🤖 GPT-4 evaluating data protection measures...")
        print("🔐 Analyzing encryption, privacy, and data security...")
        print("⏳ Data protection assessment in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.evaluate_data_protection()
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
    
    def handle_custom_ai_query(self):
        """Handle custom AI-powered security query"""
        print("\n🔍 CUSTOM AI SECURITY QUERY")
        print("─" * 35)
        print("🤖 Ask GPT-4 any security question about your traffic!")
        print("💡 Examples:")
        print("   • 'What are the most critical vulnerabilities?'")
        print("   • 'How can I improve authentication security?'")
        print("   • 'What data protection issues were found?'")
        print()
        
        query = input("🧠 Ask GPT-4: ").strip()
        
        if not query:
            print("❌ Please enter a valid query")
            return
        
        if len(query) < 5:
            print("❌ Query too short. Please be more specific.")
            return
        
        print(f"\n🤖 GPT-4 analyzing: '{query}'")
        print("⏳ Advanced AI analysis in progress...")
        print("─" * 60)
        
        try:
            response = self.analyzer.analyze_security_query(query)
            print(response)
        except Exception as e:
            print(f"❌ AI Analysis failed: {e}")
            print("💡 Check OpenAI API key and try again")
    
    def show_example_queries(self):
        """Show example queries optimized for AI analysis"""
        examples = [
            "What are the top 5 critical security vulnerabilities in my application?",
            "How secure are the authentication mechanisms being used?",
            "What sensitive data is being exposed and how can I protect it?",
            "Are there any SQL injection vulnerabilities and how critical are they?",
            "What XSS risks exist and what's the recommended mitigation strategy?",
            "How can I improve the overall security posture of my application?",
            "What are the compliance risks related to data protection regulations?",
            "Are there any authentication bypass vulnerabilities?",
            "What encryption weaknesses exist in the traffic?",
            "How do the identified vulnerabilities rank by business impact?"
        ]
        
        print("\n📚 AI-OPTIMIZED SECURITY QUERIES")
        print("═" * 55)
        print("🤖 These queries are optimized for GPT-4 analysis:")
        print()
        
        for i, example in enumerate(examples, 1):
            print(f"{i:2d}. {example}")
        
        print("\n" + "═" * 55)
        print("💡 Use these in 'Custom AI Security Query' for best results!")
    
    def show_system_statistics(self):
        """Show system statistics"""
        print("\n📈 SYSTEM STATISTICS")
        print("─" * 30)
        print("🤖 AI Model: OpenAI GPT-4")
        print("🔬 Analysis Framework: AutoGen Multi-Agent")
        print("�� Knowledge Storage: ChromaDB Vector Database")
        print("🕸️ Traffic Source: OWASP ZAP")
        print("🧠 Embeddings: Sentence Transformers")
        
        try:
            # Get basic ChromaDB stats
            collection = self.analyzer.collection
            doc_count = collection.count()
            print(f"📚 Knowledge Base: {doc_count} documents")
            
            if doc_count > 0:
                sample = collection.get(limit=min(10, doc_count), include=['metadatas'])
                doc_types = {}
                for metadata in sample['metadatas']:
                    doc_type = metadata.get('type', 'unknown')
                    doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
                
                print("📋 Document Types:")
                for doc_type, count in doc_types.items():
                    print(f"   • {doc_type.replace('_', ' ').title()}: {count}")
            else:
                print("⚠️ No data available - run collector first")
                
        except Exception as e:
            print(f"❌ Statistics error: {e}")
    
    def run(self):
        """Main application loop"""
        self.show_ai_banner()
        
        print("\n🚀 Welcome to the AI-Powered Security Analysis System!")
        print("\n✨ FEATURES:")
        print("   🤖 GPT-4 powered security analysis")
        print("   🔬 Multi-agent AI collaboration")
        print("   📊 Advanced vulnerability assessment")
        print("   🧠 Natural language security insights")
        print("\n💡 This system combines OWASP ZAP, AutoGen, OpenAI, and RAG")
        print("   for the most advanced security analysis available!")
        
        while True:
            try:
                self.show_enhanced_menu()
                
                choice = input("\n🎯 Select option (1-8): ").strip()
                
                if choice == '1':
                    self.handle_ai_comprehensive_analysis()
                elif choice == '2':
                    self.handle_ai_critical_vulnerabilities()
                elif choice == '3':
                    self.handle_ai_authentication_review()
                elif choice == '4':
                    self.handle_ai_data_protection()
                elif choice == '5':
                    self.handle_custom_ai_query()
                elif choice == '6':
                    self.show_system_statistics()
                elif choice == '7':
                    self.show_example_queries()
                elif choice == '8':
                    print("\n🤖 Thank you for using AI-Powered Security Analysis!")
                    print("🔒 Your applications are more secure with AI insights!")
                    print("✨ Powered by: ZAP + AutoGen + OpenAI GPT-4 + RAG")
                    break
                else:
                    print("❌ Invalid option. Please select 1-8.")
                
                # Pause after AI analysis
                if choice in ['1', '2', '3', '4', '5']:
                    print("\n" + "─" * 60)
                    input("⏎  Press Enter to return to main menu...")
                elif choice in ['6', '7']:
                    input("\n⏎  Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\n👋 AI System interrupted. Goodbye!")
                print("🤖 Keep using AI to secure your applications!")
                break
            except Exception as e:
                print(f"\n❌ System error: {e}")
                input("\n⏎  Press Enter to continue...")

def main():
    """Enhanced application entry point"""
    try:
        app = EnhancedSecurityApp()
        app.run()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("\n💡 Troubleshooting:")
        print("   • Check OpenAI API key is set")
        print("   • Ensure ZAP daemon is running")
        print("   • Run collector to gather data")
        sys.exit(1)

if __name__ == "__main__":
    main()

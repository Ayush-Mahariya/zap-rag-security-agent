# 🔒 ZAP-AutoGen-RAG Security Analysis System

**An AI-powered web application security analysis platform combining OWASP ZAP, OpenAI GPT-4, and RAG (Retrieval-Augmented Generation) for intelligent vulnerability detection and remediation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OpenAI GPT-4](https://img.shields.io/badge/AI-GPT--4-green.svg)](https://openai.com/)
[![OWASP ZAP](https://img.shields.io/badge/Security-OWASP%20ZAP-red.svg)](https://owasp.org/www-project-zap/)

## 🎯 Overview

This system revolutionizes web application security testing by combining industry-standard tools with cutting-edge AI. It captures HTTP traffic using OWASP ZAP, analyzes it with OpenAI GPT-4, and provides intelligent security insights through natural language queries.

### ✨ Key Features

- 🕸️ **HTTP Traffic Capture**: Real-time web application traffic analysis via OWASP ZAP
- 🧠 **GPT-4 AI Analysis**: Advanced vulnerability detection using OpenAI's most powerful model
- 📊 **RAG Knowledge System**: Semantic search and retrieval of security knowledge
- 💬 **Natural Language Queries**: Ask security questions in plain English
- ⚡ **Real-time Processing**: Immediate analysis of captured network traffic
- 🎯 **Vulnerability Detection**: SQL injection, XSS, authentication issues, data exposure
- 📈 **Comprehensive Reports**: Detailed security assessments with remediation steps
- ☁️ **Cloud-Ready**: Runs entirely in GitHub Codespaces

## 🏗️ Architecture

┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│ OWASP ZAP   │───▶│ Data         │───▶│ ChromaDB    │───▶│ OpenAI       │
│ (Proxy)     │    │ Collector    │    │ (Vector DB) │    │ GPT-4        │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                                                                   │
┌─────────────┐    ┌──────────────┐    ┌─────────────┐           │
│ User        │◀───│ AI Security  │◀───│ RAG Engine  │◀──────────┘
│ Interface   │    │ Analyzer     │    │             │
└─────────────┘    └──────────────┘    └─────────────┘

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- OpenAI API Key
- GitHub Codespaces (recommended) or local Linux environment

### 1. Setup Environment

```
# Clone the repository
git clone https://github.com/your-username/zap-autogen-rag-security.git
cd zap-autogen-rag-security

# Set OpenAI API Key
export OPENAI_API_KEY="your-openai-api-key-here"

# Install dependencies
poetry install
```

### 2. Download and Setup OWASP ZAP

```
# Download OWASP ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz
tar -xzf ZAP_2.15.0_Linux.tar.gz
chmod +x ZAP_2.15.0/zap.sh
```

### 3. Start OWASP ZAP Daemon

```
# Terminal 1: Start ZAP in daemon mode
./ZAP_2.15.0/zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
```

### 4. Collect Security Data

```
# Terminal 2: Run data collector
poetry run python zap_security_agent/collector.py

# Let it run for 45-60 seconds to collect sample traffic
# Press Ctrl+C to stop
```

### 5. Launch AI Security Analysis

```
# Terminal 3: Start AI analysis interface
poetry run python zap_security_agent/simple_ai_main.py
```

## 📋 Usage Examples

### AI-Powered Analysis Options

1. **🧠 AI Comprehensive Security Analysis** - Complete GPT-4 security audit
2. **⚡ AI Critical Vulnerability Assessment** - High-priority threat analysis
3. **🔐 AI Authentication Security Review** - Login and auth mechanism analysis
4. **🛡️ AI Data Protection Evaluation** - Privacy and encryption assessment
5. **🔍 Custom AI Security Query** - Ask GPT-4 any security question

### Sample Queries

```
"What are the most critical security vulnerabilities in my application?"
"How can I improve authentication security?"
"Are there any SQL injection risks and what's the impact?"
"What sensitive data is being exposed?"
"How do I fix the XSS vulnerabilities found?"
```

## 📁 Project Structure

```
zap-autogen-rag-security/
├── pyproject.toml                 # Poetry dependencies
├── poetry.lock                    # Dependency lock file
├── README.md                      # This file
├── ZAP_2.15.0/                   # OWASP ZAP installation
├── chroma_db/                     # ChromaDB persistent storage
├── test_zap_connection.py         # Connection testing utility
└── zap_security_agent/            # Main application package
    ├── __init__.py               # Package initialization
    ├── collector.py              # Traffic collection & ChromaDB storage
    ├── openai_analyzer.py        # GPT-4 security analysis engine
    └── simple_ai_main.py         # Interactive user interface
```

## 🔧 Configuration

### Environment Variables

```
# Required
export OPENAI_API_KEY="your-openai-api-key"

# Optional (defaults provided)
export ZAP_PROXY_PORT="8080"
export CHROMA_DB_PATH="./chroma_db"
```

### Default Settings

- **ZAP Proxy**: `localhost:8080`
- **ChromaDB**: Persistent storage in `./chroma_db/`
- **AI Model**: `gpt-4` (OpenAI)
- **Embedding Model**: `all-MiniLM-L6-v2`

## 🛡️ Security Analysis Capabilities

### Vulnerability Detection

- **SQL Injection**: Pattern recognition and context analysis
- **Cross-Site Scripting (XSS)**: Script injection detection
- **Authentication Issues**: Weak credentials, session management
- **Data Exposure**: Sensitive information in requests/responses
- **HTTPS Compliance**: Encryption and secure communication
- **CSRF Vulnerabilities**: State-changing request protection

### AI Analysis Features

- **Risk Assessment**: Automatic severity classification (Critical/High/Medium/Low)
- **Impact Analysis**: Business and technical impact evaluation
- **Remediation Steps**: Specific, actionable fix recommendations
- **Best Practices**: Proactive security guidance
- **Compliance Mapping**: Regulatory requirement alignment

## 🧪 Testing

```
# Test ZAP connection
poetry run python test_zap_connection.py

# Test core dependencies
poetry run python -c "import openai, chromadb, sentence_transformers; print('✅ All dependencies working')"

# Verify AI analysis
poetry run python -c "from zap_security_agent.openai_analyzer import OpenAISecurityAnalyzer; print('✅ AI analyzer ready')"
```

## 📊 Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Security Scanner** | OWASP ZAP 2.15.0 | HTTP traffic capture & analysis |
| **AI Engine** | OpenAI GPT-4 | Advanced security analysis & insights |
| **Vector Database** | ChromaDB | Semantic search & knowledge storage |
| **Embeddings** | Sentence Transformers | Text vectorization for RAG |
| **Language** | Python 3.10+ | Core application development |
| **Dependencies** | Poetry | Package management |
| **Environment** | GitHub Codespaces | Cloud development platform |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```
# Install development dependencies
poetry install --dev

# Run tests
poetry run pytest

# Format code
poetry run black .

# Lint code
poetry run flake8 .
```

## 🆘 Troubleshooting

### Common Issues

#### ZAP Connection Failed
```
# Check if ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Restart ZAP daemon
./ZAP_2.15.0/zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
```

#### No Security Data Available
```
# Run collector first to gather data
poetry run python zap_security_agent/collector.py
# Let it run for 45+ seconds before stopping
```

#### OpenAI API Issues
```
# Verify API key is set
echo $OPENAI_API_KEY

# Test API connection
poetry run python -c "import openai; print('✅ OpenAI configured')"
```

#### ChromaDB Collection Not Found
```
# Check if persistent storage exists
ls -la chroma_db/

# Re-run collector to recreate database
poetry run python zap_security_agent/collector.py
```

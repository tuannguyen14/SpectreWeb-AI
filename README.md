# 👻 Spectreweb AI v4.0

> **Self-Learning AI for Manual Penetration Testing**
>
> 🎯 Manual Testing First | Self-Learning AI | WAF Bypass | Context-Aware | Bug Bounty Ready

```
███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
               ██╗    ██╗███████╗██████╗ 
               ██║    ██║██╔════╝██╔══██╗
               ██║ █╗ ██║█████╗  ██████╔╝
               ██║███╗██║██╔══╝  ██╔══██╗
               ╚███╔███╔╝███████╗██████╔╝
                ╚══╝╚══╝ ╚══════╝╚═════╝
```

## 🎯 Tại sao Spectreweb AI khác biệt?

### ❌ Vấn đề với Auto Scanners truyền thống

| Tool | Vấn đề |
|------|--------|
| Nuclei, Nikto | Bị WAF block, signature-based, dễ detect |
| Burp Scanner | Chậm, tốn license, không AI-native |
| OWASP ZAP | Noisy, false positives nhiều |
| Automated tools | Rate limited, IP banned, miss logic bugs |

### ✅ Spectreweb AI: Manual Testing với AI

**Spectreweb không phải auto scanner** - nó là **AI-powered assistant** cho manual penetration testing:

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎯 SPECTREWEB AI PHILOSOPHY                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ❌ Auto scan → Bị block → Fail                                    │
│  ✅ AI analyze → Human decide → Smart test → Success               │
│                                                                     │
│  "Không brute force, mà outsmart"                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 🔥 Key Differentiators

| Feature | Traditional | Spectreweb AI |
|---------|-------------|--------------|
| **Approach** | Auto scan everything | AI-guided manual testing |
| **WAF Bypass** | Hope it works | Generate 10+ bypass variants |
| **Payloads** | Static wordlists | Context-aware, mutated |
| **Rate Limits** | Get blocked | Test & adapt |
| **False Positives** | Many | AI validates |
| **Logic Bugs** | Miss | AI suggests tests |
| **Session** | Start fresh | Persists findings |

## 🧠 Self-Learning AI (NEW in v4.0!)

Spectreweb AI now features a **self-learning local AI** that improves over time:

```
┌─────────────────────────────────────────────────────────────────────┐
│  🧠 SELF-LEARNING AI ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │ Your Scans   │────▶│ Learning     │────▶│ Local AI     │        │
│  │ & Feedback   │     │ Store (SQL)  │     │ Models       │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│                              │                    │                 │
│                              ▼                    ▼                 │
│                    ┌──────────────────────────────────────┐        │
│                    │         AI Orchestrator              │        │
│                    │  Local AI ←→ Remote AI (hybrid)      │        │
│                    └──────────────────────────────────────┘        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 🎓 What the AI Learns

| Model | Learns From | Purpose |
|-------|-------------|---------|
| **SecretClassifier** | Your true/false positive feedback | Reduce FP in secret detection |
| **EndpointRiskScorer** | Attack history & results | Prioritize high-risk endpoints |
| **PayloadRanker** | Which payloads worked | Select effective payloads first |

### 🚀 How It Works

```python
# 1. Scan findings are automatically stored
deep_secret_hunt("target.com")  # → Findings saved to learning store

# 2. You label findings (feedback loop)
POST /api/learning/label
{"finding_id": "secret_abc123", "label": "false_positive"}

# 3. AI learns and improves
POST /api/ai/train
# → Models retrained on your labeled data

# 4. Future scans use learned models
POST /api/ai/classify_secret
{"secret_type": "aws_key", "entropy": 4.8, "in_test_file": true}
# → {"is_real": false, "confidence": 0.85, "model_used": "ml"}
```

### 🔄 Hybrid AI Strategy

- **Local AI** (fast, free, learns from you):
  - Secret classification
  - Endpoint risk scoring
  - Payload ranking
  
- **Remote AI** (powerful, for complex tasks):
  - Deep vulnerability analysis
  - Exploit generation
  - Report writing

The orchestrator automatically routes to the best backend!

## ⚡ Core Capabilities

### 🛡️ WAF Bypass & Evasion
```python
# Generate 10+ bypass variants for any payload
waf_bypass("<script>alert(1)</script>")

# Output: URL encoded, double encoded, unicode, hex, 
#         mixed case, null byte, comments, etc.
```

### 🔀 Payload Mutation
```python
# Mutate payload with multiple techniques
mutate_payload("' OR '1'='1", "case,encode,whitespace,comments")

# Output: 15+ variations to bypass filters
```

### 🔑 IDOR Testing
```python
# Generate IDOR test cases for any ID
generate_idor_tests("12345")
# → decrement, increment, zero, negative, array injection

generate_idor_tests("550e8400-e29b-41d4-a716-446655440000")
# → null UUID, modified UUID, etc.
```

### 🔓 Auth Bypass
```python
# 26 techniques to bypass authentication
generate_auth_bypass("/admin")
# → method override, path manipulation, header bypass
```

### 👑 Privilege Escalation
```python
# Test cases for privesc
generate_privesc_tests("user")
# → role params, hidden params, JWT claims
```

### 📊 Response Analysis
```python
# Analyze error for info disclosure
analyze_error_response(error_page)
# → stack traces, DB errors, paths, versions

# Extract secrets from response
extract_secrets(response_body)
# → API keys, tokens, passwords, internal IPs
```

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/your-repo/spectreweb-ai
cd spectreweb-ai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Install Security Tools (Kali Linux)

```bash
# ProjectDiscovery tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Other tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hahwul/dalfox/v2@latest

# Add to PATH
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
```

### 3. Start Server

```bash
python server.py

# Output:
# 👻 Spectreweb AI v3.2 - Starting...
# ✅ Server running at http://127.0.0.1:8888
```

### 4. Configure MCP (for Windsurf/Claude)

```json
{
  "mcpServers": {
    "spectreweb-ai": {
      "command": "python",
      "args": ["/path/to/spectreweb-ai/mcp_client.py"],
      "env": {
        "SPECTREWEB_SERVER": "http://127.0.0.1:8888"
      }
    }
  }
}
```

## 🛠️ Tools Overview (92 MCP Tools!)

### 🎯 Manual Testing (NEW in v3.2!)

| Tool | Description |
|------|-------------|
| `mutate_payload` | 🔀 Mutate payloads with bypass techniques |
| `get_polyglot` | 🎯 Polyglot payloads for multiple contexts |
| `waf_bypass` | 🛡️ Generate WAF bypass variants |
| `test_rate_limit` | ⏱️ Test rate limiting behavior |
| `generate_idor_tests` | 🔑 IDOR test cases (numeric, UUID, b64) |
| `generate_privesc_tests` | 👑 Privilege escalation tests |
| `generate_auth_bypass` | 🔓 26 auth bypass techniques |
| `analyze_error_response` | 🔍 Info disclosure analysis |
| `extract_secrets` | 🔐 Extract secrets from responses |
| `suggest_tests` | 💡 AI-suggested next tests |

### 🧠 AI Analysis

| Tool | Description |
|------|-------------|
| `ai_analyze` | Auto-analyze for vulns & tech detection |
| `ai_detect_tech` | Identify CMS, frameworks, WAF |
| `ai_classify_endpoint` | Classify URL → attack vectors |
| `ai_get_hints` | Context-aware hunting hints |

### 📋 Smart Reporting

| Tool | Description |
|------|-------------|
| `load_context` | 🚨 Load previous findings (call first!) |
| `get_report` | Get/create persistent report |
| `add_finding` | Add finding with severity |
| `get_next_steps` | AI-suggested next steps |

### 🔍 Reconnaissance

| Tool | Description |
|------|-------------|
| `httpx_probe` | HTTP probing with tech detect |
| `subfinder_scan` | Subdomain discovery |
| `katana_crawl` | Modern web crawler |
| `waybackurls` | Historical URLs (with limit) |
| `gau_urls` | URLs from multiple sources |
| `naabu_scan` | Fast port scanning |

### ⚔️ Attack Tools

| Tool | Description |
|------|-------------|
| `test_xss` / `get_xss_advanced` | XSS with context-aware payloads |
| `test_sqli` / `get_sqli_advanced` | SQLi with DB-specific payloads |
| `test_ssrf` / `get_ssrf_bypasses` | SSRF with bypass techniques |
| `test_race` | Race condition testing |
| `test_graphql` | GraphQL introspection & attacks |
| `jwt_attack_*` | JWT none/confusion/injection |
| `get_nosql_payloads` | NoSQL injection payloads |

### 🔐 Payload & Encoding

| Tool | Description |
|------|-------------|
| `encode_payload` | URL, Base64, HTML, Hex |
| `decode_payload` | Decode any format |
| `get_wordlist` | SecLists with auto-resolve |

## 💡 Real-World Workflow

### Bug Bounty Example

```
You: "Test target.com for vulnerabilities"

Spectreweb AI:
1. 🔍 Recon: httpx_probe → Cloudflare WAF detected
2. 🛡️ Adapt: waf_bypass payloads generated
3. 🎯 Test: mutate_payload for XSS with 15 variations
4. 📊 Analyze: Found reflected input, WAF blocking <script>
5. 💡 Suggest: "Try event handlers: onerror, onload"
6. ✅ Success: <img src=x onerror=alert(1)> bypassed WAF

Finding saved → Persists across sessions
```

### Session Persistence

```
Session 1:
> "Scan api.target.com"
> Found: JWT auth, GraphQL endpoint, rate limiting at 100 req/min
> Note: "GraphQL introspection enabled"

Session 2 (new chat):
> load_context("target.com")
> AI knows everything from Session 1
> Suggests: "Test JWT none algorithm, GraphQL batching attack"
```

## 📁 Project Structure

```
spectreweb-ai/
├── server.py              # Flask server
├── mcp_client.py          # MCP client (57 tools)
├── config/
│   ├── settings.py        # Configuration
│   └── wordlists.py       # SecLists (auto-resolve)
├── core/
│   ├── executor.py        # Command execution
│   ├── analyzer.py        # AI analysis engine
│   ├── reporter.py        # Smart reporting
│   ├── context.py         # Session persistence
│   ├── learning_store.py  # 📚 Learning data storage (NEW!)
│   ├── local_ai.py        # 🧠 Self-learning ML models (NEW!)
│   ├── ai_orchestrator.py # 🔄 Hybrid AI routing (NEW!)
│   └── utils.py           # Utilities
├── web/
│   ├── client.py          # HTTP client
│   ├── manual_testing.py  # Manual testing helpers
│   ├── attack_session.py  # 🎯 Advanced attack sessions (NEW!)
│   ├── deep_secrets.py    # 🔑 Deep secret hunting (NEW!)
│   ├── advanced_attacks.py # Advanced attack techniques
│   ├── advanced_scanner.py # Vuln scanners
│   ├── exploits.py        # Exploitation helpers
│   └── payloads.py        # Payload generation
└── api/
    └── routes.py          # API endpoints
```

## 📊 Statistics

| Metric | Value |
|--------|-------|
| API Endpoints | 100+ |
| MCP Tools | 57 |
| Manual Testing Functions | 20+ |
| WAF Bypass Techniques | 10+ |
| Auth Bypass Techniques | 26 |
| Payload Mutation Methods | 7 |
| Local AI Models | 3 |
| Learning Store Tables | 4 |

## 🔒 Security Notice

⚠️ **IMPORTANT**: Only test systems you have authorization for!

- Get written permission before testing
- Respect scope and rules of engagement
- Report vulnerabilities responsibly

## 📝 License

MIT License - Use responsibly!

---

<div align="center">

**Built for Bug Bounty Hunters who think, not just scan**

# 👻 Spectreweb AI v4.0

[![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)]()
[![Tools](https://img.shields.io/badge/MCP_Tools-57-green.svg)]()
[![API](https://img.shields.io/badge/API_Endpoints-100+-orange.svg)]()
[![AI](https://img.shields.io/badge/Self--Learning_AI-Enabled-purple.svg)]()

*"AI học từ bạn, để trở nên mạnh hơn mỗi ngày"*

</div>

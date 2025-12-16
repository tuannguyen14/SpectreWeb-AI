# 👻 Spectreweb AI v4.5.3

> **Self-Learning AI for Manual Web Penetration Testing**
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

## 🎯 Why Spectreweb AI Is Different

### ❌ Problems with Traditional Auto Scanners

| Tool | Limitation |
|------|------------|
| Nuclei, Nikto | Blocked by WAFs, signature-based, easy to detect |
| Burp Scanner | Slow, expensive license, not AI-native |
| OWASP ZAP | Noisy, many false positives |
| Generic automated tools | Rate limited, IP banned, miss logic bugs |

### ✅ Spectreweb AI: Manual Testing with AI

**Spectreweb is not an auto scanner** – it is an **AI-powered assistant** for manual penetration testing:

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎯 SPECTREWEB AI PHILOSOPHY                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ❌ Auto scan → Blocked by WAF → Fail                               │
│  ✅ AI analyzes → Human decides → Smart tests → Success             │
│                                                                     │
│  "Don’t brute force the target – outsmart it."                     |
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 🔥 Key Differentiators

| Feature | Traditional | Spectreweb AI |
|---------|-------------|--------------|
| **Approach** | Blind auto-scanning | AI-guided, operator-driven testing |
| **WAF Bypass** | Hope it works | Generate 10+ smart bypass variants |
| **Payloads** | Static wordlists | Context-aware, mutated payloads |
| **Rate Limits** | Get blocked | Detect, adapt, and throttle |
| **False Positives** | Many | AI-assisted validation |
| **Logic Bugs** | Often missed | AI suggests business-logic test cases |
| **Session** | Stateless | Persists findings and context |

## 🧠 Self-Learning AI (NEW in v4.5.3!)

Spectreweb AI includes a **self-learning local AI** that becomes smarter with your usage:

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
| **SecretClassifier** | Your true/false positive feedback | Reduce false positives in secret detection |
| **EndpointRiskScorer** | Attack history & results | Prioritize high-risk endpoints |
| **PayloadRanker** | Payloads that actually worked | Prefer effective payloads first |

### 🚀 How It Works (Automatic!)

```python
# 1. Just use the tools normally - data is collected automatically!
deep_secret_hunt("target.com")     # → Secrets saved to learning store
attack_session.run_attack(...)     # → Attack results saved to learning store

# 2. Label findings to teach the AI (via MCP tools or API)
learning_label("secret_abc123", "false_positive")
learning_label("secret_xyz789", "true_positive")

# 3. Auto-train when ready (or manually trigger)
ai_auto_train()   # → Trains if 50+ labeled samples & 10+ new since last train
ai_train()        # → Force train immediately

# 4. Get smart insights from your history
ai_insights()
# → {"attack_effectiveness": {"sqli": 0.15, "xss": 0.08}, "recommendations": [...]}

# 5. Future scans use learned models automatically!
ai_classify_secret(secret_type="aws_key", entropy=4.8, in_test_file=True)
# → {"is_real": false, "confidence": 0.85, "model_used": "ml"}
```

### 🔧 MCP Tools for Self-Learning

| Tool | Description |
|------|-------------|
| `ai_status` | Get AI models & learning store status |
| `ai_train` | Manually train models |
| `ai_auto_train` | Auto-train if enough new data |
| `ai_insights` | Get smart recommendations from history |
| `ai_classify_secret` | Classify a secret using local AI |
| `ai_score_endpoint` | Score endpoint vulnerability risk |
| `learning_stats` | View learning store statistics |
| `learning_list_findings` | List stored findings |
| `learning_label` | Label a finding (feedback loop) |
| `learning_export` | Export learning data to JSON |

### 🔄 Hybrid AI Strategy

- **Local AI** (fast, free, personalized):
  - Secret classification
  - Endpoint risk scoring
  - Payload ranking
  
- **Remote AI** (heavier, for complex reasoning):
  - Deep vulnerability analysis
  - Exploit ideation and refinement
  - Report drafting and polishing

The AI orchestrator automatically chooses the most appropriate backend.

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

### 2. Install Security Tools (Recommended on Kali Linux)

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

### 3. Start the Spectreweb Server

```bash
python server.py

# Output:
# 👻 Spectreweb AI v4.5.3 - Starting...
# ✅ Server running at http://127.0.0.1:8888
```

### 4. Configure MCP (for Windsurf / Claude / MCP-compatible clients)

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

## 🛠️ Tools Overview (60+ MCP Tools)

### 🎯 Manual Testing (Operator-First)

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
├── mcp_client.py          # MCP client (67 tools)
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
| API Endpoints | 110+ |
| MCP Tools | 67 |
| Manual Testing Functions | 20+ |
| WAF Bypass Techniques | 10+ |
| Auth Bypass Techniques | 26 |
| Payload Mutation Methods | 7 |
| Local AI Models | 3 |
| Learning Store Tables | 4 |
| Self-Learning MCP Tools | 10 |

## 🔒 Legal & Ethical Use

⚠️ **IMPORTANT**: Only test systems you are explicitly authorized to test.

- Obtain written permission before any assessment.
- Respect scope, rate limits, and rules of engagement.
- Follow responsible disclosure practices when reporting vulnerabilities.

## 📝 License

MIT License – Use responsibly.

---

<div align="center">

**Built for bug bounty hunters and security engineers who think, not just scan.**

# 👻 Spectreweb AI v4.5.3

[![Version](https://img.shields.io/badge/version-4.1.0-blue.svg)]()
[![Tools](https://img.shields.io/badge/MCP_Tools-67-green.svg)]()
[![API](https://img.shields.io/badge/API_Endpoints-110+-orange.svg)]()
[![AI](https://img.shields.io/badge/Self--Learning_AI-Enabled-purple.svg)]()

*"AI that learns from your hacking style and becomes stronger every day."*

</div>

# 👻 SpectreWeb AI v7.0.0

> **AI-Assisted Manual Web Penetration Testing**
>
> 🎯 Manual Testing First | WAF Bypass | Context-Aware | Bug Bounty Ready

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

SpectreWeb is an **MCP server** that exposes a curated set of penetration-testing
tools to AI agents (Windsurf, Claude Desktop, or any MCP-compatible client). It is
designed for **operator-driven manual testing** — the AI helps you recon, fuzz,
generate payloads, and analyze responses, while you stay in control of the testing
strategy.

## 🎯 Philosophy

```
┌─────────────────────────────────────────────────────────────────────┐
│  ❌ Blind auto-scan → Blocked by WAF → Fail                         │
│  ✅ AI analyzes → Operator decides → Smart targeted tests → Success │
└─────────────────────────────────────────────────────────────────────┘
```

| Feature | Traditional Scanners | SpectreWeb AI |
|---------|----------------------|---------------|
| **Approach** | Blind auto-scanning | AI-guided, operator-driven |
| **WAF Bypass** | Hope it works | Generate bypass variants on demand |
| **Payloads** | Static wordlists | Context-aware, mutated payloads |
| **Rate Limits** | Get blocked | Per-domain throttling built in |
| **Session** | Stateless | Persists findings & context per target |

## 🏗️ Architecture

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────────┐
│  AI Agent    │──MCP──▶│  mcp_client.py   │──HTTP─▶│  server.py       │
│ (Windsurf...)│       │  (53 MCP tools)  │       │  (Flask API)     │
└──────────────┘       └──────────────────┘       └────────┬─────────┘
                                                            │
                          ┌─────────────────────────────────┼─────────────────────┐
                          ▼                 ▼                ▼                      ▼
                     core/plugin.py    core/analyzer.py  web/secrets.py     web/exploits.py
                     (tool wrappers)   (tech fingerprint)(secret scanning)  (payload gen)
```

- **`mcp_client.py`** — MCP server exposing 53 tools, forwards to the HTTP API.
- **`server.py`** — Flask app hosting the REST API.
- **`api/routes.py`** — All HTTP endpoints.
- **`core/`** — Command execution, tech analysis, reporting, context, plugins.
- **`web/`** — HTTP client, payload generation, secret scanning, exploit helpers, origin IP finder.

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/tuannguyen14/SpectreWeb-AI
cd SpectreWeb-AI

python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Install Security Tools (optional, for tool wrappers)

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

echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
```

> Tools that are not installed simply report "not installed"; the rest keep working.

### 3. Start the Server

```bash
python server.py
# 👻 SpectreWeb AI v7.0.0 - Starting...
# ✅ Server running at http://127.0.0.1:8888
```

### 4. Configure MCP

```json
{
  "mcpServers": {
    "spectreweb-ai": {
      "command": "python",
      "args": ["/path/to/SpectreWeb-AI/mcp_client.py", "--server", "http://127.0.0.1:8888"],
      "timeout": 1500,
      "alwaysAllow": []
    }
  }
}
```

## 🔐 Authentication

API authentication is **disabled by default** (local-use friendly). To enable it,
set an API key before starting the server:

```bash
export SPECTREWEB_API_KEY="your-secret-key"   # Windows: set SPECTREWEB_API_KEY=...
python server.py
```

When enabled, send the key via the `X-API-Key` header or `Authorization: Bearer <key>`.

## 🔧 Environment Variables

All configuration is done via environment variables. No hardcoded keys.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTREWEB_API_KEY` | *(none)* | API authentication key. If unset, auth is disabled |
| `SPECTREWEB_SECLISTS_PATH` | auto-detect | Path to SecLists directory (see SecLists Configuration below) |

### Origin IP Finder (optional API keys)

All Origin IP Finder techniques work **without any API key**. The following
env vars enable **optional** enhanced data sources:

| Variable | Free tier | Description |
|----------|-----------|-------------|
| `SPECTREWEB_SECURITYTRAILS_API_KEY` | ~50 queries/month | Historical DNS A records (find IPs before CDN was enabled) |
| `SPECTREWEB_SHODAN_API_KEY` | OSS plan (limited) | Shodan search API (cert pivot, favicon hash). InternetDB is free without key |
| `SPECTREWEB_CENSYS_API_ID` | ~250 queries/month | Censys cert search + favicon pivot |
| `SPECTREWEB_CENSYS_API_SECRET` | (paired with API_ID) | Censys API secret |
| `SPECTREWEB_FOFA_EMAIL` | \u26a0\ufe0f Paid only | FOFA account email. Free tier has 1000 points but API search needs F-points (paid) |
| `SPECTREWEB_FOFA_API_KEY` | \u26a0\ufe0f Paid only | FOFA API key. Favicon hash + cert search, strong for Asian targets. Needs F-points |
| `SPECTREWEB_QUAKE_API_KEY` | \u2705 Free (3000 credits) | Quake 360 API key. Cert/favicon/body search, best Asian coverage. **Free tier works!** |
| `SPECTREWEB_VALIDIN_TOKEN` | Free account | Validin API token. Passive DNS host pivot (optional, needs free account) |

**Setup (Linux):**

```bash
export SPECTREWEB_SECURITYTRAILS_API_KEY="your-key"
export SPECTREWEB_SHODAN_API_KEY="your-key"
export SPECTREWEB_CENSYS_API_ID="your-id"
export SPECTREWEB_CENSYS_API_SECRET="your-secret"
export SPECTREWEB_QUAKE_API_KEY="your-quake-key"  # free tier works!
# export SPECTREWEB_FOFA_EMAIL="your-email"          # paid only (F-points)
# export SPECTREWEB_FOFA_API_KEY="your-fofa-key"      # paid only (F-points)
python server.py
```

**Setup (Windows PowerShell):**

```powershell
$env:SPECTREWEB_SECURITYTRAILS_API_KEY = "your-key"
$env:SPECTREWEB_SHODAN_API_KEY = "your-key"
$env:SPECTREWEB_QUAKE_API_KEY = "your-quake-key"  # free tier works!
# $env:SPECTREWEB_FOFA_EMAIL = "your-email"          # paid only (F-points)
# $env:SPECTREWEB_FOFA_API_KEY = "your-fofa-key"      # paid only (F-points)
python server.py
```

> ⚠️ **Never commit API keys to git.** Use a `.env` file (add to `.gitignore`)
> or inject via CI/CD secrets.

## 📚 SecLists Configuration

SpectreWeb uses [SecLists](https://github.com/danielmiessler/SecLists) as its wordlist provider.
The server auto-detects SecLists from common paths:

| OS | Auto-detect paths |
|----|-------------------|
| **Linux** | `/usr/share/SecLists`, `/usr/share/seclists`, `/opt/SecLists`, `/opt/seclists` |
| **Windows** | `D:\SecLists`, `C:\SecLists`, `%PROGRAMFILES%\SecLists` |

### Option A: Install SecLists (recommended)

```bash
# Linux
git clone https://github.com/danielmiessler/SecLists /usr/share/SecLists

# Windows
git clone https://github.com/danielmiessler/SecLists D:\SecLists
```

### Option B: Custom path

If SecLists is installed elsewhere, set the environment variable before starting the server:

```bash
# Linux
export SPECTREWEB_SECLISTS_PATH="/your/custom/SecLists"

# Windows (PowerShell)
$env:SPECTREWEB_SECLISTS_PATH = "E:\Tools\SecLists"
```

### Available wordlists (42)

SpectreWeb ships with 42 pre-configured wordlists across 8 categories:

| Category | Wordlists | Examples |
|----------|-----------|---------|
| **Directory** | `common`, `big`, `dir_small`, `dir_medium`, `dir_big`, `raft_medium_dirs`, `combined_dirs` | Standard → exhaustive directory enumeration |
| **API** | `api_endpoints`, `api_objects`, `api_wild`, `graphql` | REST/GraphQL endpoint discovery |
| **Subdomain** | `subdomains_5k`, `subdomains_20k`, `subdomains_110k` | Quick → exhaustive subdomain enum |
| **Vuln payloads** | `sqli`, `sqli_blind`, `sqli_quick`, `sqli_polyglots`, `nosql`, `xss`, `xss_polyglot`, `lfi`, `lfi_linux`, `ssti`, `xxe`, `cmd_injection` | Injection & fuzzing payloads |
| **Auth** | `passwords`, `usernames`, `default_creds`, `tomcat_creds`, `mysql_creds`, `postgres_creds` | Brute force & default credentials |
| **Bypass** | `sqli_auth_bypass`, `sqli_mysql_bypass`, `login_bypass` | Auth/WAF bypass payloads |
| **CMS** | `wordpress`, `joomla`, `drupal` | CMS-specific paths |
| **Sensitive** | `backup_files`, `quickhits`, `login_pages` | Sensitive file & login page discovery |

### Using wordlists in MCP tools

```python
# Pass wordlist name to ffuf_scan
ffuf_scan(url="https://target.com", wordlist="common")

# Or use a custom path
ffuf_scan(url="https://target.com", wordlist="/path/to/custom.txt")

# Get wordlist info
get_wordlist(name="api_wild")

# Get suggestions based on task
suggest_wordlist(task="nosql injection testing")
```

## 🛠️ MCP Tools (53 total)

### Core (3)
| Tool | Description |
|------|-------------|
| `execute_command` | Run any shell command on the server |
| `health_check` | Server health, DB & disk status |
| `web_request` | Browser-like HTTP request |

### Reconnaissance (8)
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning & service detection |
| `naabu_scan` | Fast port scanner |
| `subfinder_scan` | Subdomain discovery (capped at 500) |
| `httpx_probe` | HTTP probing with tech detect |
| `whatweb_scan` | Technology fingerprinting |
| `ffuf_scan` | Directory/file fuzzing |
| `katana_crawl` | Web crawler (capped at 500 URLs) |
| `historical_urls` | Wayback / GAU historical URLs |

### Vulnerability Testing (3)
| Tool | Description |
|------|-------------|
| `vuln_test` | Unified XSS/SQLi/LFI/SSRF/redirect/CRLF test |
| `sqlmap_scan` | SQL injection testing |
| `dalfox_scan` | Advanced XSS scanner |

### Payloads & Bypass (4)
| Tool | Description |
|------|-------------|
| `get_payloads` | Payloads for XSS/SQLi/LFI/SSRF/SSTI/XXE/NoSQL/polyglot |
| `generate_bypass` | WAF / auth / cache-poison / 403 bypass payloads |
| `mutate_payload` | Mutate a payload with bypass techniques |
| `encode_decode` | URL / Base64 / HTML / Hex / Unicode |

### Secrets (4)
| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan text/URL/JS for hardcoded secrets |
| `secrets_hunt` | Multi-stage deep secret hunt on a domain |
| `secrets_js_hunt` | Scan multiple JS files for secrets |
| `secrets_local_scan` | Scan local files/dirs (no network) |

### JavaScript & Web Analysis (2)
| Tool | Description |
|------|-------------|
| `analyze_js` | Endpoints, secrets, DOM-XSS from JS |
| `extract_from_webpage` | Extract links/forms/comments/JS |

### Access Control & Logic (3)
| Tool | Description |
|------|-------------|
| `generate_access_tests` | IDOR / privesc / auth-bypass test cases |
| `get_business_logic_tests` | Business-logic vulnerability test cases |
| `discover_params` | Hidden parameter discovery (Arjun) |

### Specialized Attacks (4)
| Tool | Description |
|------|-------------|
| `jwt_tools` | JWT analyze / none / confusion / inject |
| `test_concurrency` | Race condition & rate-limit testing |
| `test_graphql` | GraphQL introspection & batching |
| `check_takeover` | Subdomain takeover detection |

### Analysis (3)
| Tool | Description |
|------|-------------|
| `analyze_hash` | Hash identification & crack hints |
| `test_cors` | CORS misconfiguration testing |
| `compare_responses` | Diff two responses (access control) |

### AI Analysis (1)
| Tool | Description |
|------|-------------|
| `ai_analyze` | Heuristic analysis: scan result / tech detect / classify endpoint / hints / summary |

### Reporting & Context (4)
| Tool | Description |
|------|-------------|
| `report` | Persistent report: get / add_finding / add_note / summary / next_steps |
| `load_context` | 🚨 Load previous findings (call first!) |
| `list_targets` | List previously scanned targets |
| `learning_stats` | Stored findings statistics |

### Wordlists & Files (5)
| Tool | Description |
|------|-------------|
| `get_wordlist` | Fetch wordlist by name |
| `suggest_wordlist` | Suggest wordlists for a task |
| `create_file` | Create a file on the server |
| `read_file` | Read a file from the server |
| `list_files` | List files in a directory |

### Learning Store (1)
| Tool | Description |
|------|-------------|
| `learning_list_findings` | List stored findings (review history) |

### Origin IP Finder (8)
| Tool | Free? | Description |
|------|-------|-------------|
| `find_origin_ip` | ✅ | Full orchestrator: crt.sh + subdomain leak/brute + DNS + passive DNS + Quake + Shodan + verify |
| `verify_origin_ip` | ✅ | Verify an IP serves a domain via Host header + SSL cert match |
| `cert_transparency` | ✅ | Query crt.sh Certificate Transparency logs for subdomains & cert domains |
| `shodan_lookup` | ✅ | Query Shodan InternetDB for an IP (free, no key — ports, hostnames, tags, vulns) |
| `fofa_search` | ⚠️ Paid | Search FOFA by query (cert, favicon hash, body). Free tier has no API search credits |
| `quake_search` | ✅ Free | Search Quake 360 by query (cert, favicon, body). **Free tier works!** Best Asian data |
| `passive_dns_lookup` | ✅ | Query OTX + HackerTarget + Validin for historical IPs (free, no key) |
| `subdomain_brute` | ✅ | Brute-force subdomains using SecLists wordlist (5K/20K/110K, multi-threaded) |

## 💡 Example Workflow

```
You: "Test target.com for vulnerabilities"

SpectreWeb AI:
1. load_context("target.com")        → Recall any prior findings
2. httpx_probe / whatweb_scan         → Cloudflare WAF detected
3. generate_bypass("waf", payload)    → Build evasion variants
4. vuln_test("xss", url)              → Probe with context-aware payloads
5. report("add_finding", ...)         → Persist the result
```

## 📁 Project Structure

```
SpectreWeb-AI/
├── server.py              # Flask server
├── mcp_client.py          # MCP client (53 tools)
├── config/
│   ├── settings.py        # Configuration
│   └── wordlists.py       # SecLists (auto-resolve)
├── core/
│   ├── executor.py        # Command execution
│   ├── plugin.py          # Tool plugins (nmap, ffuf, httpx, ...)
│   ├── analyzer.py        # Tech fingerprint & heuristic analysis
│   ├── reporter.py        # Persistent reporting
│   ├── context.py         # Per-target session persistence
│   ├── learning_store.py  # SQLite findings store
│   ├── middleware.py      # Auth, rate limiting, error handling
│   ├── job_queue.py       # Background job queue
│   └── file_manager.py    # Sandboxed file ops
├── web/
│   ├── client.py          # HTTP client with retry & rate limiting
│   ├── manual_testing.py  # Manual testing helpers
│   ├── deep_secrets.py    # Multi-stage secret hunting
│   ├── origin_finder.py  # Origin IP discovery (bypass CDN/WAF)
│   ├── advanced_scanner.py# Vuln scanners
│   ├── exploits.py        # Exploitation / payload helpers
│   ├── secrets.py         # Secret pattern scanning
│   └── payloads.py        # Payload generation
└── api/
    └── routes.py          # HTTP API endpoints
```

## 🔒 Legal & Ethical Use

⚠️ **Only test systems you are explicitly authorized to test.**

- Obtain written permission before any assessment.
- Respect scope, rate limits, and rules of engagement.
- Follow responsible disclosure practices.

## 📝 License

MIT License — Use responsibly.

---

<div align="center">

**Built for bug bounty hunters and security engineers who think, not just scan.**

[![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)]()
[![Tools](https://img.shields.io/badge/MCP_Tools-53-green.svg)]()

</div>

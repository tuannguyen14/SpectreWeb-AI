"""
SpectreWeb AI Smart Context System

Automatically loads and organizes context before AI starts scanning.
Maintains intelligent directory structure for multiple targets.
"""

import os
import json
import hashlib
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional
import glob
from urllib.parse import urlparse

from core.url_utils import extract_domain, extract_root_domain

REPORTS_BASE_DIR = "/tmp/spectreweb/targets"

class TargetContext:
    """
    Smart context management for a target domain.
    
    Directory Structure:
    /tmp/spectreweb/targets/
    └── example.com/
        ├── _meta.json           # Domain metadata
        ├── _report.json         # Main domain report
        ├── subdomains/
        │   ├── api.example.com/
        │   │   └── _report.json
        │   └── wallet.example.com/
        │       └── _report.json
        ├── scans/
        │   ├── 20241128_143000_nmap.json
        │   └── 20241128_143500_ffuf.json
        └── notes/
            └── session_notes.md
    """
    
    def __init__(self, target: str):
        self.original_target = target
        self.domain = self._extract_domain(target)
        self.subdomain = self._extract_subdomain(target)
        self.base_dir = os.path.join(REPORTS_BASE_DIR, self.domain)
        
        # Initialize directory structure
        self._init_directories()
        
        # Load existing context
        self.meta = self._load_meta()
        self.previous_findings = []
        self.previous_notes = []
        self.known_subdomains = []
        self.known_technologies = []
        self.known_endpoints = []
        self.scan_history = []
        
        self._load_context()
    
    def _extract_domain(self, target: str) -> str:
        """Extract root domain from target"""
        return extract_root_domain(target) or target
    
    def _extract_subdomain(self, target: str) -> Optional[str]:
        """Extract subdomain if present"""
        domain = extract_domain(target)
        root = extract_root_domain(target)
        if domain and root and domain != root:
            # Subdomain is the part before root domain
            if domain.endswith(root):
                subdomain = domain[:-len(root)].rstrip('.')
                return subdomain if subdomain else None
        return None
    
    def _init_directories(self):
        """Create directory structure"""
        dirs = [
            self.base_dir,
            os.path.join(self.base_dir, "subdomains"),
            os.path.join(self.base_dir, "scans"),
            os.path.join(self.base_dir, "notes"),
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
    
    def _load_meta(self) -> Dict:
        """Load or create domain metadata"""
        meta_path = os.path.join(self.base_dir, "_meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                return json.load(f)
        
        meta = {
            "domain": self.domain,
            "created_at": datetime.now().isoformat(),
            "last_scan": None,
            "total_scans": 0,
            "total_findings": 0,
        }
        self._save_meta(meta)
        return meta
    
    def _save_meta(self, meta: Dict = None):
        """Save domain metadata"""
        meta_path = os.path.join(self.base_dir, "_meta.json")
        with open(meta_path, 'w') as f:
            json.dump(meta or self.meta, f, indent=2)
    
    def _load_context(self):
        """Load all existing context for this domain"""
        # Load main report
        report_path = os.path.join(self.base_dir, "_report.json")
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                data = json.load(f)
                self.previous_findings = data.get('findings', [])
                self.previous_notes = data.get('notes', [])
                self.known_technologies = data.get('technologies', [])
                self.known_endpoints = data.get('endpoints', [])
                self.known_subdomains = data.get('subdomains', [])
        
        # Load subdomain reports
        subdomain_dir = os.path.join(self.base_dir, "subdomains")
        if os.path.exists(subdomain_dir):
            for sub_dir in os.listdir(subdomain_dir):
                sub_report = os.path.join(subdomain_dir, sub_dir, "_report.json")
                if os.path.exists(sub_report):
                    if sub_dir not in self.known_subdomains:
                        self.known_subdomains.append(sub_dir)
        
        # Load scan history
        scans_dir = os.path.join(self.base_dir, "scans")
        if os.path.exists(scans_dir):
            for scan_file in sorted(glob.glob(os.path.join(scans_dir, "*.json")))[-10:]:
                try:
                    with open(scan_file, 'r') as f:
                        scan_data = json.load(f)
                        self.scan_history.append({
                            "file": os.path.basename(scan_file),
                            "tool": scan_data.get('tool'),
                            "timestamp": scan_data.get('timestamp'),
                            "success": scan_data.get('success')
                        })
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
    
    def get_ai_briefing(self) -> str:
        """
        Generate a briefing for AI before starting scan.
        This should be called at the START of any scanning session.
        """
        briefing = f"""
# 👻 SpectreWeb AI Context Briefing
**Target Domain:** {self.domain}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Previous Intelligence

### Known Technologies
{', '.join(self.known_technologies) if self.known_technologies else '⚠️ No technologies identified yet - run whatweb_scan first'}

### Known Subdomains ({len(self.known_subdomains)})
"""
        if self.known_subdomains:
            # Categorize subdomains
            api_subs = [s for s in self.known_subdomains if 'api' in s.lower()]
            dev_subs = [s for s in self.known_subdomains if any(x in s.lower() for x in ['dev', 'staging', 'test', 'stag'])]
            other_subs = [s for s in self.known_subdomains if s not in api_subs and s not in dev_subs]
            
            if api_subs:
                briefing += f"\n**🔗 API Endpoints:** {', '.join(api_subs[:5])}"
            if dev_subs:
                briefing += f"\n**🔬 Dev/Staging:** {', '.join(dev_subs[:5])}"
            if other_subs:
                briefing += f"\n**🌐 Other:** {', '.join(other_subs[:10])}"
            if len(self.known_subdomains) > 20:
                briefing += f"\n... and {len(self.known_subdomains) - 20} more"
        else:
            briefing += "⚠️ No subdomains found yet - run subfinder_scan first\n"
        
        briefing += f"""

### Known Endpoints ({len(self.known_endpoints)})
"""
        if self.known_endpoints:
            for ep in self.known_endpoints[:10]:
                briefing += f"- {ep}\n"
        else:
            briefing += "⚠️ No endpoints discovered yet - run ffuf_scan or katana_crawl\n"
        
        briefing += f"""

### Previous Findings ({len(self.previous_findings)})
"""
        if self.previous_findings:
            critical_high = [f for f in self.previous_findings if f.get('severity') in ['critical', 'high']]
            if critical_high:
                briefing += "**🔴 Critical/High:**\n"
                for f in critical_high[:5]:
                    briefing += f"- {f.get('title')} ({f.get('severity')})\n"
            medium_low = [f for f in self.previous_findings if f.get('severity') in ['medium', 'low']]
            if medium_low:
                briefing += f"**🟡 Medium/Low:** {len(medium_low)} findings\n"
        else:
            briefing += "No vulnerabilities found yet\n"
        
        briefing += f"""

### Notes from Previous Sessions
"""
        if self.previous_notes:
            for note in self.previous_notes[-5:]:
                briefing += f"- {note}\n"
        else:
            briefing += "No notes from previous sessions\n"
        
        briefing += f"""

### Recent Scan History
"""
        if self.scan_history:
            for scan in self.scan_history[-5:]:
                status = "✅" if scan.get('success') else "❌"
                briefing += f"- {status} {scan.get('tool')} ({scan.get('timestamp', 'unknown')[:16]})\n"
        else:
            briefing += "No previous scans recorded\n"
        
        # Recommendations
        briefing += """

## 🎯 Recommended Actions Based on Context

"""
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations, 1):
            briefing += f"{i}. {rec}\n"
        
        return briefing
    
    def _generate_recommendations(self) -> List[str]:
        """Generate smart recommendations based on current context"""
        recs = []
        
        # No subdomains
        if not self.known_subdomains:
            recs.append("🔍 Run `subfinder_scan` to discover subdomains")
        elif len(self.known_subdomains) > 0:
            api_subs = [s for s in self.known_subdomains if 'api' in s.lower()]
            if api_subs:
                recs.append(f"🔗 Test API endpoints on {api_subs[0]} for IDOR, auth bypass")
        
        # No technologies
        if not self.known_technologies:
            recs.append("🔎 Run `whatweb_scan` to identify technologies")
        else:
            if 'WordPress' in self.known_technologies:
                recs.append("📝 WordPress detected - check /wp-admin, /xmlrpc.php, run WPScan")
            if 'nginx' in str(self.known_technologies).lower():
                recs.append("⚙️ nginx detected - check for misconfigurations, path traversal")
        
        # No endpoints
        if not self.known_endpoints:
            recs.append("🕷️ Run `katana_crawl` or `ffuf_scan` to discover endpoints")
        
        # No findings
        if not self.previous_findings:
            recs.append("💉 Start vulnerability testing: test_xss, test_sqli, test_lfi")
        
        # Based on notes
        for note in self.previous_notes:
            if 'api' in note.lower() and 'test' in note.lower():
                recs.append("📝 Previous note mentioned API testing - continue investigation")
                break
        
        if not recs:
            recs.append("🎯 Deep dive: test for business logic flaws, race conditions")
            recs.append("🔐 Try auth bypass techniques on discovered endpoints")
        
        return recs[:5]
    
    def save_scan_result(self, tool: str, result: Dict, target: Optional[str] = None):
        """Save scan result to organized directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{tool}.json"
        filepath = os.path.join(self.base_dir, "scans", filename)

        scan_target = target or result.get('url') or self.original_target
        
        scan_data = {
            "tool": tool,
            "timestamp": datetime.now().isoformat(),
            "target": scan_target,
            "success": result.get('success', False),
            "result": result
        }
        
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        # Update meta
        self.meta['last_scan'] = datetime.now().isoformat()
        self.meta['total_scans'] = self.meta.get('total_scans', 0) + 1
        self._save_meta()
        
        return filepath
    
    def add_subdomain(self, subdomain: str):
        """Add a subdomain and create its directory"""
        if subdomain not in self.known_subdomains:
            self.known_subdomains.append(subdomain)
            # Create subdomain directory
            sub_dir = os.path.join(self.base_dir, "subdomains", subdomain)
            os.makedirs(sub_dir, exist_ok=True)
    
    def add_subdomains(self, subdomains: List[str]):
        """Add multiple subdomains"""
        for sub in subdomains:
            self.add_subdomain(sub)
    
    def save_report(self, report_data: Dict, target: Optional[str] = None):
        """Save report to appropriate location"""
        effective_target = target or report_data.get("target") or report_data.get("url") or self.original_target
        subdomain = self._extract_subdomain(effective_target) if effective_target else None

        if subdomain:
            # Save to subdomain directory
            sub_dir = os.path.join(self.base_dir, "subdomains", f"{subdomain}.{self.domain}")
            os.makedirs(sub_dir, exist_ok=True)
            report_path = os.path.join(sub_dir, "_report.json")
        else:
            report_path = os.path.join(self.base_dir, "_report.json")
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def add_note(self, note: str):
        """Add note to session notes"""
        notes_file = os.path.join(self.base_dir, "notes", "session_notes.md")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        with open(notes_file, 'a') as f:
            f.write(f"\n## [{timestamp}]\n{note}\n")
        
        self.previous_notes.append(f"[{timestamp}] {note}")


# Global context cache
_contexts: Dict[str, TargetContext] = {}
_contexts_lock = threading.Lock()

def get_context(target: str) -> TargetContext:
    """Get or create context for target"""
    domain = extract_root_domain(target) or target
    with _contexts_lock:
        if domain not in _contexts:
            _contexts[domain] = TargetContext(target)
        return _contexts[domain]

def load_target_context(target: str) -> Dict[str, Any]:
    """
    Load context for a target and return AI briefing.
    
    This should be called by AI BEFORE starting any scan.
    Returns structured data for AI consumption.
    """
    ctx = get_context(target)
    
    return {
        "success": True,
        "target": target,
        "domain": ctx.domain,
        "briefing": ctx.get_ai_briefing(),
        "stats": {
            "known_subdomains": len(ctx.known_subdomains),
            "known_endpoints": len(ctx.known_endpoints),
            "known_technologies": ctx.known_technologies,
            "previous_findings": len(ctx.previous_findings),
            "previous_notes": len(ctx.previous_notes),
            "total_scans": ctx.meta.get('total_scans', 0)
        },
        "recommendations": ctx._generate_recommendations(),
        "last_scan": ctx.meta.get('last_scan'),
        "directory": ctx.base_dir
    }

def list_all_targets() -> Dict[str, Any]:
    """List all targets that have been scanned"""
    targets = []
    
    if os.path.exists(REPORTS_BASE_DIR):
        for domain in os.listdir(REPORTS_BASE_DIR):
            domain_path = os.path.join(REPORTS_BASE_DIR, domain)
            if os.path.isdir(domain_path):
                meta_path = os.path.join(domain_path, "_meta.json")
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                        targets.append({
                            "domain": domain,
                            "last_scan": meta.get('last_scan'),
                            "total_scans": meta.get('total_scans', 0),
                            "total_findings": meta.get('total_findings', 0)
                        })
    
    return {
        "success": True,
        "targets": sorted(targets, key=lambda x: x.get('last_scan') or '', reverse=True),
        "total": len(targets)
    }

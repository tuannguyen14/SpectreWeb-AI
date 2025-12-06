"""
SpectreWeb AI Smart Report System

Automatically generates structured reports after scans that can be
understood by future AI sessions to maintain context and avoid missing findings.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import os

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingType(Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    SUBDOMAIN = "subdomain"
    PARAMETER = "parameter"
    NOTE = "note"

@dataclass
class Finding:
    """Single security finding"""
    type: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    recommendation: str = ""
    cvss: float = 0.0
    cwe: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ScanResult:
    """Result of a single tool scan"""
    tool: str
    target: str
    timestamp: str
    duration: float
    success: bool
    raw_output: str = ""
    findings: List[Finding] = None
    metadata: Dict = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.metadata is None:
            self.metadata = {}

class SpectreReport:
    """
    Smart Report Generator for AI Pentesting
    
    Features:
    - Structured findings for AI consumption
    - Cross-session persistence
    - Automatic deduplication
    - Priority scoring
    - Next steps suggestions
    """
    
    def __init__(self, target: str, report_dir: str = "/tmp/spectreweb/reports"):
        self.target = target
        self.target_id = hashlib.md5(target.encode()).hexdigest()[:12]
        self.report_dir = report_dir
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.created_at = datetime.now().isoformat()
        
        self.scan_results: List[ScanResult] = []
        self.findings: List[Finding] = []
        self.technologies: List[str] = []
        self.subdomains: List[str] = []
        self.endpoints: List[str] = []
        self.parameters: List[str] = []
        self.notes: List[str] = []
        
        # Ensure report dir exists
        os.makedirs(report_dir, exist_ok=True)
        
        # Load existing report if exists
        self._load_existing()
    
    def _get_report_path(self) -> str:
        return os.path.join(self.report_dir, f"{self.target_id}.json")
    
    def _load_existing(self):
        """Load existing report for this target"""
        path = self._get_report_path()
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                    self.technologies = data.get('technologies', [])
                    self.subdomains = data.get('subdomains', [])
                    self.endpoints = data.get('endpoints', [])
                    self.parameters = data.get('parameters', [])
                    self.notes = data.get('notes', [])
                    # Load findings
                    for f_data in data.get('findings', []):
                        self.findings.append(Finding(**f_data))
            except:
                pass
    
    def add_scan_result(self, tool: str, target: str, output: Dict, duration: float = 0):
        """Add result from a tool scan"""
        result = ScanResult(
            tool=tool,
            target=target,
            timestamp=datetime.now().isoformat(),
            duration=duration,
            success=output.get('success', False),
            raw_output=output.get('stdout', ''),
            metadata=output
        )
        self.scan_results.append(result)
        
        # Auto-extract findings based on tool
        self._auto_extract(tool, output)
        
        return result
    
    def _auto_extract(self, tool: str, output: Dict):
        """Automatically extract findings from tool output"""
        
        if tool == "whatweb":
            # Extract technologies
            stdout = output.get('stdout', '')
            techs = []
            for tech in ['WordPress', 'nginx', 'Apache', 'PHP', 'jQuery', 
                        'React', 'Vue', 'Angular', 'Node.js', 'Cloudflare']:
                if tech.lower() in stdout.lower():
                    techs.append(tech)
            self.add_technologies(techs)
            
        elif tool == "subfinder":
            # Extract subdomains
            stdout = output.get('stdout', '')
            subs = [s.strip() for s in stdout.split('\n') if s.strip()]
            self.add_subdomains(subs)
            
        elif tool == "ffuf":
            # Extract endpoints
            stdout = output.get('stdout', '')
            for line in stdout.split('\n'):
                if '[Status:' in line:
                    parts = line.split()
                    if parts:
                        self.add_endpoint(parts[0].strip())
                        
        elif tool in ["test_xss", "test_sqli", "test_lfi"]:
            # Check for vulnerabilities
            if output.get('vulnerable', False):
                vuln_type = tool.replace('test_', '').upper()
                self.add_finding(Finding(
                    type=FindingType.VULNERABILITY.value,
                    severity=Severity.HIGH.value,
                    title=f"{vuln_type} Vulnerability Detected",
                    description=f"Application is vulnerable to {vuln_type}",
                    url=output.get('url', ''),
                    evidence=str(output.get('results', []))
                ))
    
    def add_finding(self, finding: Finding):
        """Add a security finding (with deduplication)"""
        # Check for duplicates
        for f in self.findings:
            if f.title == finding.title and f.url == finding.url:
                return  # Already exists
        self.findings.append(finding)
    
    def add_technologies(self, techs: List[str]):
        """Add detected technologies"""
        for tech in techs:
            if tech and tech not in self.technologies:
                self.technologies.append(tech)
    
    def add_subdomains(self, subs: List[str]):
        """Add discovered subdomains"""
        for sub in subs:
            if sub and sub not in self.subdomains:
                self.subdomains.append(sub)
    
    def add_endpoint(self, endpoint: str):
        """Add discovered endpoint"""
        if endpoint and endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
    
    def add_parameter(self, param: str):
        """Add discovered parameter"""
        if param and param not in self.parameters:
            self.parameters.append(param)
    
    def add_note(self, note: str):
        """Add manual note for future AI sessions"""
        if note and note not in self.notes:
            self.notes.append(f"[{datetime.now().strftime('%H:%M')}] {note}")
    
    def get_next_steps(self) -> List[str]:
        """Generate intelligent next steps based on findings"""
        steps = []
        
        # Based on technologies
        if 'WordPress' in self.technologies:
            steps.append("🎯 Run WPScan for WordPress vulnerabilities")
            steps.append("🔍 Check /wp-admin, /wp-login.php, /xmlrpc.php")
        
        if 'Cloudflare' in self.technologies:
            steps.append("⚡ Try to find origin IP behind Cloudflare")
            steps.append("🔍 Check historical DNS records")
        
        # Based on subdomains
        if self.subdomains:
            api_subs = [s for s in self.subdomains if 'api' in s.lower()]
            if api_subs:
                steps.append(f"🔗 Test API endpoints on: {', '.join(api_subs[:3])}")
            
            dev_subs = [s for s in self.subdomains if any(x in s.lower() for x in ['dev', 'staging', 'test'])]
            if dev_subs:
                steps.append(f"🔬 Check development environments: {', '.join(dev_subs[:3])}")
        
        # Based on endpoints
        if '/admin' in str(self.endpoints):
            steps.append("🔐 Test admin panel for default credentials")
        
        # Based on findings
        high_findings = [f for f in self.findings if f.severity in ['critical', 'high']]
        if high_findings:
            steps.append("⚠️ Prioritize exploitation of high severity findings")
        
        # Generic suggestions
        if not self.findings:
            steps.append("🕷️ Run deeper fuzzing with more wordlists")
            steps.append("🔍 Check for hidden parameters with Arjun")
            steps.append("📝 Test for business logic vulnerabilities")
        
        return steps
    
    def generate_summary(self) -> str:
        """Generate AI-friendly summary"""
        summary = f"""
# 🎯 SpectreWeb AI Report
**Target:** {self.target}
**Session:** {self.session_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Statistics
- **Scans Completed:** {len(self.scan_results)}
- **Total Findings:** {len(self.findings)}
- **Critical/High:** {len([f for f in self.findings if f.severity in ['critical', 'high']])}
- **Subdomains:** {len(self.subdomains)}
- **Endpoints:** {len(self.endpoints)}
- **Technologies:** {', '.join(self.technologies) or 'None detected'}

## 🔴 High Priority Findings
"""
        # Add high priority findings
        high = [f for f in self.findings if f.severity in ['critical', 'high']]
        if high:
            for f in high[:5]:
                summary += f"- **{f.title}** ({f.severity}): {f.description[:100]}...\n"
        else:
            summary += "- No critical/high findings yet\n"
        
        summary += "\n## 🌐 Key Subdomains\n"
        for sub in self.subdomains[:10]:
            summary += f"- {sub}\n"
        if len(self.subdomains) > 10:
            summary += f"- ... and {len(self.subdomains) - 10} more\n"
        
        summary += "\n## 📍 Interesting Endpoints\n"
        for ep in self.endpoints[:10]:
            summary += f"- {ep}\n"
        
        summary += "\n## 🚀 Recommended Next Steps\n"
        for step in self.get_next_steps():
            summary += f"{step}\n"
        
        if self.notes:
            summary += "\n## 📝 Notes from Previous Sessions\n"
            for note in self.notes[-5:]:
                summary += f"- {note}\n"
        
        return summary
    
    def to_dict(self) -> Dict:
        """Convert report to dictionary"""
        return {
            'target': self.target,
            'target_id': self.target_id,
            'session_id': self.session_id,
            'created_at': self.created_at,
            'updated_at': datetime.now().isoformat(),
            'technologies': self.technologies,
            'subdomains': self.subdomains,
            'endpoints': self.endpoints,
            'parameters': self.parameters,
            'notes': self.notes,
            'findings': [f.to_dict() for f in self.findings],
            'scan_results': [
                {
                    'tool': r.tool,
                    'target': r.target,
                    'timestamp': r.timestamp,
                    'duration': r.duration,
                    'success': r.success
                } for r in self.scan_results
            ],
            'summary': self.generate_summary(),
            'next_steps': self.get_next_steps()
        }
    
    def save(self):
        """Save report to disk"""
        path = self._get_report_path()
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        return path
    
    def to_json(self) -> str:
        """Export as JSON string"""
        return json.dumps(self.to_dict(), indent=2)


# Global report instance (per target)
_reports: Dict[str, SpectreReport] = {}

def get_report(target: str) -> SpectreReport:
    """Get or create report for target"""
    target_id = hashlib.md5(target.encode()).hexdigest()[:12]
    if target_id not in _reports:
        _reports[target_id] = SpectreReport(target)
    return _reports[target_id]

def auto_report(tool: str, target: str, output: Dict, duration: float = 0) -> Dict:
    """
    Automatically add scan result to report.
    Call this after each tool execution.
    """
    report = get_report(target)
    report.add_scan_result(tool, target, output, duration)
    report.save()
    return {
        "report_updated": True,
        "findings_count": len(report.findings),
        "summary": report.generate_summary()
    }

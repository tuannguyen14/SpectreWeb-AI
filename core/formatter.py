#!/usr/bin/env python3
"""
SpectreWeb AI - Smart Output Formatter v5.0.2
Beautiful real-time output with colors, tables, and progress bars
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class Color:
    """ANSI Color codes for terminal output"""
    # Basic colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    
    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    # Reset
    RESET = "\033[0m"
    
    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output"""
        for attr in dir(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, '')


class Severity(Enum):
    """Vulnerability severity levels with colors"""
    CRITICAL = ("CRITICAL", Color.BG_RED + Color.WHITE + Color.BOLD, "🔴")
    HIGH = ("HIGH", Color.RED + Color.BOLD, "🟠")
    MEDIUM = ("MEDIUM", Color.YELLOW, "🟡")
    LOW = ("LOW", Color.BLUE, "🔵")
    INFO = ("INFO", Color.CYAN, "ℹ️")


@dataclass
class ScanResult:
    """Structured scan result"""
    tool: str
    target: str
    status: str
    findings: List[Dict]
    duration: float
    timestamp: str


class SpectreFormatter:
    """Smart output formatter for SpectreWeb AI"""
    
    BANNER = f"""
{Color.CYAN}{Color.BOLD}
   ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
   ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
   ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
{Color.MAGENTA}        ██╗    ██╗███████╗██████╗ 
        ██║    ██║██╔════╝██╔══██╗
        ██║ █╗ ██║█████╗  ██████╔╝
        ██║███╗██║██╔══╝  ██╔══██╗
        ╚███╔███╔╝███████╗██████╔╝
         ╚══╝╚══╝ ╚══════╝╚═════╝ {Color.RESET}
{Color.GRAY}     👻 Phantom Recon Engine v5.0.2{Color.RESET}
"""

    BOX_CHARS = {
        'tl': '╭', 'tr': '╮', 'bl': '╰', 'br': '╯',
        'h': '─', 'v': '│', 'lj': '├', 'rj': '┤',
        'tj': '┬', 'bj': '┴', 'cross': '┼'
    }
    
    def __init__(self, width: int = 80):
        self.width = width
    
    # ==================== BOXES & FRAMES ====================
    
    def box(self, content: str, title: str = "", color: str = Color.CYAN) -> str:
        """Create a beautiful box around content"""
        lines = content.split('\n')
        max_len = max(len(line) for line in lines) if lines else 0
        max_len = max(max_len, len(title) + 4)
        
        b = self.BOX_CHARS
        result = []
        
        # Top border with title
        if title:
            title_str = f" {title} "
            padding = max_len - len(title) - 2
            result.append(f"{color}{b['tl']}{b['h']}{Color.BOLD}{title_str}{Color.RESET}{color}{b['h'] * padding}{b['tr']}{Color.RESET}")
        else:
            result.append(f"{color}{b['tl']}{b['h'] * (max_len + 2)}{b['tr']}{Color.RESET}")
        
        # Content
        for line in lines:
            padding = max_len - len(line)
            result.append(f"{color}{b['v']}{Color.RESET} {line}{' ' * padding} {color}{b['v']}{Color.RESET}")
        
        # Bottom border
        result.append(f"{color}{b['bl']}{b['h'] * (max_len + 2)}{b['br']}{Color.RESET}")
        
        return '\n'.join(result)
    
    def header(self, text: str, icon: str = "👻") -> str:
        """Create a section header"""
        line = "═" * (self.width - 4)
        return f"\n{Color.CYAN}{Color.BOLD}╔{line}╗\n║ {icon} {text.upper()}{' ' * (self.width - len(text) - 8)}║\n╚{line}╝{Color.RESET}\n"
    
    def divider(self, char: str = "─", color: str = Color.GRAY) -> str:
        """Create a divider line"""
        return f"{color}{char * self.width}{Color.RESET}"
    
    # ==================== TABLES ====================
    
    def table(self, headers: List[str], rows: List[List[str]], title: str = "") -> str:
        """Create a formatted table"""
        # Calculate column widths
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width + 2)
        
        b = self.BOX_CHARS
        result = []
        
        # Title
        if title:
            result.append(f"\n{Color.BOLD}{Color.CYAN}📊 {title}{Color.RESET}")
        
        # Top border
        top = b['tl'] + b['tj'].join(b['h'] * w for w in col_widths) + b['tr']
        result.append(f"{Color.GRAY}{top}{Color.RESET}")
        
        # Header row
        header_row = b['v'] + b['v'].join(
            f"{Color.BOLD}{Color.CYAN}{h.center(col_widths[i])}{Color.RESET}"
            for i, h in enumerate(headers)
        ) + b['v']
        result.append(header_row)
        
        # Header separator
        sep = b['lj'] + b['cross'].join(b['h'] * w for w in col_widths) + b['rj']
        result.append(f"{Color.GRAY}{sep}{Color.RESET}")
        
        # Data rows
        for row in rows:
            row_str = b['v'] + b['v'].join(
                f" {str(row[i] if i < len(row) else '').ljust(col_widths[i] - 2)} "
                for i in range(len(headers))
            ) + b['v']
            result.append(f"{Color.GRAY}{row_str}{Color.RESET}")
        
        # Bottom border
        bottom = b['bl'] + b['bj'].join(b['h'] * w for w in col_widths) + b['br']
        result.append(f"{Color.GRAY}{bottom}{Color.RESET}")
        
        return '\n'.join(result)
    
    # ==================== PROGRESS & STATUS ====================
    
    def progress_bar(self, current: int, total: int, width: int = 40, 
                     prefix: str = "", suffix: str = "") -> str:
        """Create a progress bar"""
        if total == 0:
            percent = 100
        else:
            percent = int((current / total) * 100)
        
        filled = int(width * current / total) if total > 0 else width
        bar = "█" * filled + "░" * (width - filled)
        
        # Color based on progress
        if percent < 33:
            color = Color.RED
        elif percent < 66:
            color = Color.YELLOW
        else:
            color = Color.GREEN
        
        return f"{prefix} {color}[{bar}]{Color.RESET} {percent}% {suffix}"
    
    def spinner_frames(self) -> List[str]:
        """Return spinner animation frames"""
        return ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def status(self, message: str, status: str = "info") -> str:
        """Format a status message"""
        icons = {
            "info": ("ℹ️", Color.CYAN),
            "success": ("✅", Color.GREEN),
            "warning": ("⚠️", Color.YELLOW),
            "error": ("❌", Color.RED),
            "running": ("🔄", Color.BLUE),
            "found": ("🎯", Color.MAGENTA),
            "scan": ("🔍", Color.CYAN),
            "vuln": ("🚨", Color.RED + Color.BOLD),
        }
        icon, color = icons.get(status, ("•", Color.WHITE))
        timestamp = datetime.now().strftime("%H:%M:%S")
        return f"{Color.GRAY}[{timestamp}]{Color.RESET} {icon} {color}{message}{Color.RESET}"
    
    # ==================== FINDINGS & VULNERABILITIES ====================
    
    def finding(self, title: str, severity: str, description: str, 
                evidence: str = "", recommendation: str = "") -> str:
        """Format a security finding"""
        sev = getattr(Severity, severity.upper(), Severity.INFO)
        sev_name, sev_color, sev_icon = sev.value
        
        result = [
            f"\n{sev_icon} {sev_color}[{sev_name}]{Color.RESET} {Color.BOLD}{title}{Color.RESET}",
            f"   {Color.GRAY}Description:{Color.RESET} {description}",
        ]
        
        if evidence:
            result.append(f"   {Color.GRAY}Evidence:{Color.RESET} {Color.YELLOW}{evidence}{Color.RESET}")
        if recommendation:
            result.append(f"   {Color.GRAY}Fix:{Color.RESET} {Color.GREEN}{recommendation}{Color.RESET}")
        
        return '\n'.join(result)
    
    def vuln_summary(self, findings: List[Dict]) -> str:
        """Create a vulnerability summary"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        
        bars = []
        colors = [
            ("CRIT", counts["critical"], Color.BG_RED + Color.WHITE),
            ("HIGH", counts["high"], Color.RED),
            ("MED", counts["medium"], Color.YELLOW),
            ("LOW", counts["low"], Color.BLUE),
            ("INFO", counts["info"], Color.CYAN),
        ]
        
        for name, count, color in colors:
            if count > 0:
                bars.append(f"{color}[{name}: {count}]{Color.RESET}")
        
        return f"📊 {Color.BOLD}Findings:{Color.RESET} " + " ".join(bars) if bars else f"📊 {Color.GREEN}No findings{Color.RESET}"
    
    # ==================== SCAN OUTPUT ====================
    
    def scan_header(self, tool: str, target: str) -> str:
        """Format scan start header"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""
{Color.CYAN}╭{'─' * 60}╮{Color.RESET}
{Color.CYAN}│{Color.RESET} {Color.BOLD}🔍 {tool.upper()}{Color.RESET}{' ' * (52 - len(tool))}{Color.CYAN}│{Color.RESET}
{Color.CYAN}│{Color.RESET} {Color.GRAY}Target:{Color.RESET} {target[:48]}{' ' * max(0, 48 - len(target))}{Color.CYAN}│{Color.RESET}
{Color.CYAN}│{Color.RESET} {Color.GRAY}Time:{Color.RESET}   {timestamp}{' ' * 29}{Color.CYAN}│{Color.RESET}
{Color.CYAN}╰{'─' * 60}╯{Color.RESET}"""
    
    def scan_result(self, tool: str, result: Dict, duration: float = 0) -> str:
        """Format scan result"""
        success = result.get("success", False)
        status_icon = "✅" if success else "❌"
        status_color = Color.GREEN if success else Color.RED
        
        lines = [
            f"\n{status_color}{status_icon} {tool} completed{Color.RESET} {Color.GRAY}({duration:.2f}s){Color.RESET}"
        ]
        
        # Extract key info based on tool type
        if "stdout" in result and result["stdout"]:
            output_lines = result["stdout"].strip().split('\n')
            if len(output_lines) <= 10:
                for line in output_lines:
                    lines.append(f"   {Color.GRAY}│{Color.RESET} {line}")
            else:
                for line in output_lines[:5]:
                    lines.append(f"   {Color.GRAY}│{Color.RESET} {line}")
                lines.append(f"   {Color.GRAY}│{Color.RESET} {Color.DIM}... ({len(output_lines) - 10} more lines) ...{Color.RESET}")
                for line in output_lines[-5:]:
                    lines.append(f"   {Color.GRAY}│{Color.RESET} {line}")
        
        return '\n'.join(lines)
    
    # ==================== AI INSIGHTS ====================
    
    def ai_insight(self, insight: str, category: str = "tip") -> str:
        """Format an AI insight or recommendation"""
        icons = {
            "tip": ("💡", Color.YELLOW),
            "warning": ("⚠️", Color.YELLOW),
            "attack": ("⚔️", Color.RED),
            "idea": ("🧠", Color.MAGENTA),
            "next": ("➡️", Color.CYAN),
        }
        icon, color = icons.get(category, ("•", Color.WHITE))
        return f"{icon} {color}{Color.ITALIC}{insight}{Color.RESET}"
    
    def ai_thinking(self, thought: str) -> str:
        """Format AI thinking process"""
        return f"{Color.GRAY}{Color.DIM}🤔 Analyzing: {thought}...{Color.RESET}"
    
    def recommendations(self, recs: List[str]) -> str:
        """Format a list of recommendations"""
        result = [f"\n{Color.BOLD}{Color.CYAN}🎯 Recommended Next Steps:{Color.RESET}"]
        for i, rec in enumerate(recs, 1):
            result.append(f"   {Color.YELLOW}{i}.{Color.RESET} {rec}")
        return '\n'.join(result)
    
    # ==================== JSON & DATA ====================
    
    def json_highlight(self, data: Any, indent: int = 2) -> str:
        """Pretty print JSON with syntax highlighting"""
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                return data
        
        json_str = json.dumps(data, indent=indent, ensure_ascii=False)
        
        # Highlight syntax
        json_str = re.sub(r'"([^"]+)":', f'{Color.CYAN}"\\1"{Color.RESET}:', json_str)
        json_str = re.sub(r': "([^"]*)"', f': {Color.GREEN}"\\1"{Color.RESET}', json_str)
        json_str = re.sub(r': (\d+)', f': {Color.YELLOW}\\1{Color.RESET}', json_str)
        json_str = re.sub(r': (true|false|null)', f': {Color.MAGENTA}\\1{Color.RESET}', json_str)
        
        return json_str
    
    def key_value(self, key: str, value: Any, color: str = Color.CYAN) -> str:
        """Format a key-value pair"""
        return f"{color}{key}:{Color.RESET} {value}"
    
    # ==================== SUMMARY & REPORTS ====================
    
    def scan_summary(self, target: str, scans: int, findings: int, 
                     duration: float, subdomains: int = 0) -> str:
        """Create a scan session summary"""
        return f"""
{Color.CYAN}{'═' * 60}{Color.RESET}
{Color.BOLD}📋 SCAN SUMMARY{Color.RESET}
{Color.CYAN}{'─' * 60}{Color.RESET}
  {Color.GRAY}Target:{Color.RESET}      {target}
  {Color.GRAY}Scans:{Color.RESET}       {scans}
  {Color.GRAY}Findings:{Color.RESET}    {Color.YELLOW if findings > 0 else Color.GREEN}{findings}{Color.RESET}
  {Color.GRAY}Subdomains:{Color.RESET}  {subdomains}
  {Color.GRAY}Duration:{Color.RESET}    {duration:.2f}s
{Color.CYAN}{'═' * 60}{Color.RESET}"""
    
    def mini_report(self, target: str, findings: List[Dict]) -> str:
        """Create a mini report card"""
        crit = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        med = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        
        risk_score = crit * 10 + high * 5 + med * 2
        if risk_score >= 20:
            risk = (f"{Color.RED}CRITICAL{Color.RESET}", "🔴")
        elif risk_score >= 10:
            risk = (f"{Color.YELLOW}HIGH{Color.RESET}", "🟠")
        elif risk_score >= 5:
            risk = (f"{Color.YELLOW}MEDIUM{Color.RESET}", "🟡")
        else:
            risk = (f"{Color.GREEN}LOW{Color.RESET}", "🟢")
        
        return f"""
{Color.BOLD}┌─────────────────────────────────────┐{Color.RESET}
{Color.BOLD}│{Color.RESET}  {risk[1]} {Color.BOLD}Risk Level: {risk[0]}{' ' * 10}{Color.BOLD}│{Color.RESET}
{Color.BOLD}├─────────────────────────────────────┤{Color.RESET}
{Color.BOLD}│{Color.RESET}  Target: {target[:25]:<25}{Color.BOLD}│{Color.RESET}
{Color.BOLD}│{Color.RESET}  Critical: {Color.RED}{crit}{Color.RESET} High: {Color.YELLOW}{high}{Color.RESET} Medium: {med:<3}{Color.BOLD}│{Color.RESET}
{Color.BOLD}└─────────────────────────────────────┘{Color.RESET}"""


# Global formatter instance
fmt = SpectreFormatter()


# Convenience functions
def print_banner():
    print(SpectreFormatter.BANNER)

def print_status(msg: str, status: str = "info"):
    print(fmt.status(msg, status))

def print_finding(title: str, severity: str, desc: str, evidence: str = "", rec: str = ""):
    print(fmt.finding(title, severity, desc, evidence, rec))

def print_scan_header(tool: str, target: str):
    print(fmt.scan_header(tool, target))

def print_scan_result(tool: str, result: Dict, duration: float = 0):
    print(fmt.scan_result(tool, result, duration))

def print_table(headers: List[str], rows: List[List[str]], title: str = ""):
    print(fmt.table(headers, rows, title))

def print_ai_insight(insight: str, category: str = "tip"):
    print(fmt.ai_insight(insight, category))

def print_recommendations(recs: List[str]):
    print(fmt.recommendations(recs))

def print_box(content: str, title: str = "", color: str = Color.CYAN):
    print(fmt.box(content, title, color))

def print_summary(target: str, scans: int, findings: int, duration: float, subdomains: int = 0):
    print(fmt.scan_summary(target, scans, findings, duration, subdomains))

"""
Plugin Architecture for Tools

Provides a standardized interface for security tools (nmap, ffuf, katana, etc.)
to enable easy integration and consistent behavior.
"""

import subprocess
import shutil
import shlex
import os
import time
import threading
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    FUZZER = "fuzzer"
    CRAWLER = "crawler"
    EXPLOIT = "exploit"
    UTILITY = "utility"


@dataclass
class ToolResult:
    """Standardized tool execution result"""
    success: bool
    tool_name: str
    command: str = ""
    output: str = ""
    parsed_data: Any = None
    error: str = None
    duration_seconds: float = 0.0
    exit_code: int = None
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "tool": self.tool_name,
            "command": self.command,
            "output": self.output[:50000] if self.output else None,
            "data": self.parsed_data,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 2),
            "exit_code": self.exit_code,
            "metadata": self.metadata
        }


class BaseTool(ABC):
    """
    Base class for all security tools.
    
    To create a new tool:
    1. Subclass BaseTool
    2. Set name, category, binary_name
    3. Implement build_command() and parse_output()
    4. Register with ToolRegistry
    
    Example:
        class NmapTool(BaseTool):
            name = "nmap"
            category = ToolCategory.SCANNER
            binary_name = "nmap"
            
            def build_command(self, target: str, **kwargs) -> List[str]:
                return ["nmap", "-sV", target]
            
            def parse_output(self, output: str, exit_code: int) -> Any:
                return {"raw": output}
    """
    
    name: str = "base_tool"
    category: ToolCategory = ToolCategory.UTILITY
    binary_name: str = ""
    description: str = ""
    default_timeout: int = 300
    
    def __init__(self):
        self._binary_path: Optional[str] = None
    
    @property
    def binary_path(self) -> Optional[str]:
        """Get path to tool binary - works for any user (root or regular)"""
        if self._binary_path is None:
            # Build dynamic candidate paths for any system/user
            candidates = []
            
            # Current user's go bin
            candidates.append(os.path.expanduser(f"~/go/bin/{self.binary_name}"))
            
            # Common home directories for go binaries
            for home in ["/root", "/home"]:
                if home == "/home" and os.path.isdir("/home"):
                    # Check all user home directories
                    try:
                        for user in os.listdir("/home"):
                            user_go_bin = f"/home/{user}/go/bin/{self.binary_name}"
                            if user_go_bin not in candidates:
                                candidates.append(user_go_bin)
                    except PermissionError:
                        pass
                else:
                    candidates.append(f"{home}/go/bin/{self.binary_name}")
            
            # System-wide locations
            candidates.extend([
                f"/usr/local/go/bin/{self.binary_name}",
                f"/usr/local/bin/{self.binary_name}",
                f"/usr/bin/{self.binary_name}",
                f"/opt/go/bin/{self.binary_name}",
            ])
            
            # Check each candidate
            for path in candidates:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    self._binary_path = path
                    break
            
            # Fallback to PATH-based resolution
            if self._binary_path is None:
                self._binary_path = shutil.which(self.binary_name)
        return self._binary_path
    
    def is_available(self) -> bool:
        """Check if tool is installed and available"""
        return self.binary_path is not None
    
    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """
        Build command line arguments.
        
        Args:
            target: Primary target (URL, IP, domain)
            **kwargs: Tool-specific options
        
        Returns:
            List of command arguments
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: str, exit_code: int) -> Any:
        """
        Parse tool output into structured data.
        
        Args:
            output: Raw stdout/stderr from tool
            exit_code: Process exit code
        
        Returns:
            Parsed data (dict, list, etc.)
        """
        pass
    
    def validate_target(self, target: str) -> Optional[str]:
        """
        Validate target format.
        
        Returns:
            Error message if invalid, None if valid
        """
        if not target or not isinstance(target, str):
            return "Target is required"
        return None
    
    def run(
        self,
        target: str,
        timeout: int = None,
        realtime: bool = False,
        stdout_callback = None,
        stderr_callback = None,
        **kwargs
    ) -> ToolResult:
        """
        Execute the tool.
        
        Args:
            target: Primary target
            timeout: Execution timeout in seconds
            realtime: If True, use streaming execution with realtime logging
            stdout_callback: Callback function for stdout lines
            stderr_callback: Callback function for stderr lines
            **kwargs: Tool-specific options
        
        Returns:
            ToolResult with output and parsed data
        """
        # Check availability
        if not self.is_available():
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=f"Tool '{self.binary_name}' not found in PATH"
            )
        
        # Validate target
        validation_error = self.validate_target(target)
        if validation_error:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=validation_error
            )
        
        # Build command
        try:
            stdin_data = None
            if "stdin" in kwargs:
                stdin_data = kwargs.pop("stdin")
            elif "input_data" in kwargs:
                stdin_data = kwargs.pop("input_data")

            if isinstance(stdin_data, str) and stdin_data and not stdin_data.endswith("\n"):
                stdin_data += "\n"

            cmd = self.build_command(target, **kwargs)
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=f"Failed to build command: {e}"
            )
        
        # Execute
        timeout = timeout or self.default_timeout
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        
        # Use realtime streaming execution if requested or if callbacks are provided
        if realtime or stdout_callback or stderr_callback:
            return self._run_realtime(cmd, cmd_str, timeout, stdin_data, stdout_callback, stderr_callback)
        
        # Standard blocking execution
        start_time = time.time()
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data
            )
            
            duration = time.time() - start_time
            stdout = process.stdout or ""
            stderr = process.stderr or ""
            output = stdout + stderr
            parse_source = stdout if stdout.strip() else output
            
            # Parse output
            try:
                parsed = self.parse_output(parse_source, process.returncode)
            except Exception as e:
                parsed = {"parse_error": str(e), "raw": parse_source}
            
            return ToolResult(
                success=process.returncode == 0,
                tool_name=self.name,
                command=cmd_str,
                output=output,
                parsed_data=parsed,
                duration_seconds=duration,
                exit_code=process.returncode
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=cmd_str,
                error=f"Timeout after {timeout} seconds",
                duration_seconds=timeout
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=cmd_str if cmd else "",
                error=str(e),
                duration_seconds=time.time() - start_time
            )

    def _run_realtime(
        self,
        cmd: List[str],
        cmd_str: str,
        timeout: int,
        stdin_data: str = None,
        stdout_callback = None,
        stderr_callback = None
    ) -> ToolResult:
        """
        Execute with realtime streaming output (logs each line as it arrives).
        """
        from .executor import CommandExecutor
        
        # CommandExecutor expects a shell command string
        # For stdin-fed tools, we need to pipe the input
        if stdin_data:
            # Use echo to pipe stdin data to the command
            escaped_stdin = shlex.quote(stdin_data.rstrip('\n'))
            shell_cmd = f"echo {escaped_stdin} | {cmd_str}"
        else:
            shell_cmd = cmd_str
        
        executor = CommandExecutor(shell_cmd, timeout=timeout, stdout_callback=stdout_callback, stderr_callback=stderr_callback)
        result = executor.execute()
        
        output = result.get("output", "")
        parse_source = result.get("stdout", "") or output
        
        # Parse output
        exit_code = result.get("return_code", 1)
        try:
            parsed = self.parse_output(parse_source, exit_code)
        except Exception as e:
            parsed = {"parse_error": str(e), "raw": parse_source}
        
        return ToolResult(
            success=result.get("success", False),
            tool_name=self.name,
            command=shell_cmd,
            output=output,
            parsed_data=parsed,
            duration_seconds=result.get("execution_time", 0),
            exit_code=exit_code,
            error=result.get("error")
        )


class ToolRegistry:
    """
    Registry for tool plugins.
    
    Usage:
        registry = ToolRegistry()
        registry.register(NmapTool)
        
        # Get tool instance
        nmap = registry.get("nmap")
        result = nmap.run("192.168.1.1")
        
        # List available tools
        tools = registry.list_available()
    """
    
    _instance: Optional['ToolRegistry'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._tools: Dict[str, Type[BaseTool]] = {}
                    cls._instance._instances: Dict[str, BaseTool] = {}
        return cls._instance
    
    def register(self, tool_class: Type[BaseTool]):
        """Register a tool class"""
        self._tools[tool_class.name] = tool_class
    
    def get(self, name: str) -> Optional[BaseTool]:
        """Get tool instance by name"""
        if name not in self._instances:
            tool_class = self._tools.get(name)
            if tool_class:
                self._instances[name] = tool_class()
        return self._instances.get(name)
    
    def list_all(self) -> List[Dict]:
        """List all registered tools"""
        return [
            {
                "name": tool_class.name,
                "category": tool_class.category.value,
                "description": tool_class.description,
                "binary": tool_class.binary_name,
                "available": self.get(tool_class.name).is_available()
            }
            for tool_class in self._tools.values()
        ]
    
    def list_available(self) -> List[str]:
        """List names of available (installed) tools"""
        return [
            name for name, tool_class in self._tools.items()
            if self.get(name).is_available()
        ]
    
    def by_category(self, category: ToolCategory) -> List[str]:
        """Get tool names by category"""
        return [
            name for name, tool_class in self._tools.items()
            if tool_class.category == category
        ]


# Global registry
_registry = ToolRegistry()


def register_tool(tool_class: Type[BaseTool]):
    """Decorator to register a tool"""
    _registry.register(tool_class)
    return tool_class


def get_tool(name: str) -> Optional[BaseTool]:
    """Get tool from global registry"""
    return _registry.get(name)


def list_tools() -> List[Dict]:
    """List all registered tools"""
    return _registry.list_all()


# Built-in tool implementations

@register_tool
class NmapTool(BaseTool):
    """Nmap port scanner"""
    name = "nmap"
    category = ToolCategory.SCANNER
    binary_name = "nmap"
    description = "Network port scanner and service detection"
    default_timeout = 600
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "nmap"]
        
        scan_type = kwargs.get("scan_type", "-sV")
        if scan_type:
            cmd.extend(scan_type.split())
        
        ports = kwargs.get("ports", "")
        if ports:
            cmd.extend(["-p", ports])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        cmd.append(target)
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        lines = output.split('\n')
        ports = []
        host_info = {}
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    })
            elif 'Host is' in line:
                host_info["status"] = "up" if "up" in line.lower() else "down"
        
        return {
            "ports": ports,
            "host_info": host_info,
            "port_count": len(ports)
        }


@register_tool
class FfufTool(BaseTool):
    """Ffuf web fuzzer"""
    name = "ffuf"
    category = ToolCategory.FUZZER
    binary_name = "ffuf"
    description = "Fast web fuzzer for directory and parameter discovery"
    default_timeout = 300

    def _sanitize_additional_args(self, additional: str) -> List[str]:
        if not additional:
            return []
        try:
            parts = shlex.split(str(additional))
        except Exception:
            return []

        forbidden_with_value = {"-u", "-w", "-o", "-of", "--wordlist"}
        forbidden_prefixes = ("-u=", "-w=", "-o=", "-of=", "--wordlist=")

        sanitized: List[str] = []
        i = 0
        while i < len(parts):
            p = parts[i]
            if p in forbidden_with_value:
                i += 2
                continue
            if any(p.startswith(pref) for pref in forbidden_prefixes):
                i += 1
                continue
            sanitized.append(p)
            i += 1
        return sanitized
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        # Ensure URL contains FUZZ keyword for fuzzing
        if "FUZZ" not in target:
            if target.endswith("/"):
                target = target + "FUZZ"
            else:
                target = target + "/FUZZ"
        
        cmd = [self.binary_path or "ffuf", "-s", "-u", target]
        
        wordlist = kwargs.get("wordlist", "common")
        raw_wordlist = wordlist
        
        # Handle empty or None wordlist - default to "common"
        if not wordlist or (isinstance(wordlist, str) and not wordlist.strip()):
            wordlist = "common"
            raw_wordlist = "common"
        
        # Map common dirb paths to aliases for SecLists preference
        from config import SECLISTS_PATH
        dirb_to_alias = {
            "/usr/share/wordlists/dirb/common.txt": "common",
            "/usr/share/wordlists/dirb/big.txt": "big",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt": "dir_medium",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt": "dir_small",
            f"{SECLISTS_PATH}/Discovery/Web-Content/common.txt": "common",
            f"{SECLISTS_PATH}/Discovery/Web-Content/big.txt": "big",
            f"{SECLISTS_PATH}/Discovery/Web-Content/directory-list-2.3-medium.txt": "dir_medium",
            f"{SECLISTS_PATH}/Discovery/Web-Content/directory-list-2.3-small.txt": "dir_small",
        }
        if wordlist in dirb_to_alias:
            wordlist = dirb_to_alias[wordlist]
        
        try:
            if isinstance(wordlist, str) and wordlist and "/" not in wordlist and not wordlist.startswith(".") and "." not in wordlist:
                from config import resolve_wordlist_path, WORDLISTS
                if wordlist not in WORDLISTS:
                    raise ValueError(f"Unknown wordlist: {wordlist}")
                wordlist = resolve_wordlist_path(wordlist)
        except Exception:
            pass

        # Final validation - ensure we have a valid wordlist file
        if not isinstance(wordlist, str) or not wordlist or not os.path.exists(wordlist):
            raise ValueError(f"Wordlist not found or invalid: {raw_wordlist}")
        cmd.extend(["-w", wordlist])
        
        match_codes = kwargs.get("match_codes", "200,301,302,403")
        cmd.extend(["-mc", match_codes])
        
        cmd.extend(["-o", "/dev/stdout", "-of", "json"])

        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])
            elif isinstance(headers, list):
                for h in headers:
                    if isinstance(h, str) and h.strip():
                        cmd.extend(["-H", h.strip()])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(self._sanitize_additional_args(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        import json
        try:
            data = json.loads(output)
            results = data.get("results", [])
            return {
                "results": results,
                "total": len(results)
            }
        except json.JSONDecodeError:
            return {"raw": output}


@register_tool
class KatanaTool(BaseTool):
    """Katana web crawler"""
    name = "katana"
    category = ToolCategory.CRAWLER
    binary_name = "katana"
    description = "Fast web crawler for endpoint discovery"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "katana", "-u", target]
        
        depth = kwargs.get("depth", 2)
        cmd.extend(["-d", str(depth)])
        
        if kwargs.get("js_crawl", True):
            cmd.append("-jc")
        
        cmd.append("-silent")
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        urls = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            "urls": urls,
            "total": len(urls)
        }


@register_tool
class SubfinderTool(BaseTool):
    """Subfinder subdomain enumeration"""
    name = "subfinder"
    category = ToolCategory.RECON
    binary_name = "subfinder"
    description = "Subdomain discovery tool"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "subfinder", "-d", target, "-silent"]
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        subdomains = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            "subdomains": subdomains,
            "total": len(subdomains)
        }


@register_tool  
class HttpxTool(BaseTool):
    """Httpx HTTP probe"""
    name = "httpx"
    category = ToolCategory.RECON
    binary_name = "httpx"
    description = "Fast HTTP toolkit for probing"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "httpx"]

        additional = kwargs.get("additional_args", "-silent -sc -title -td")
        if additional:
            replacements = {
                "-status-code": "-sc",
                "--status-code": "-sc",
                "-tech-detect": "-td",
                "--tech-detect": "-td",
            }
            tokens = [replacements.get(tok, tok) for tok in shlex.split(additional)]
            # Always add -silent and -json for clean output
            if "-silent" not in tokens and "--silent" not in tokens:
                tokens.insert(0, "-silent")
            if "-json" not in tokens and "--json" not in tokens:
                tokens.append("-json")
            cmd.extend(tokens)

        return cmd

    def run(self, target: str, timeout: int = None, stdout_callback=None, stderr_callback=None, **kwargs) -> ToolResult:
        # httpx can read targets from stdin (supports multi-line input)
        return super().run(target, timeout=timeout, stdin=target, stdout_callback=stdout_callback, stderr_callback=stderr_callback, **kwargs)
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        import json
        results = []
        for line in output.split('\n'):
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    continue
        return {
            "results": results,
            "total": len(results)
        }


@register_tool
class WhatwebTool(BaseTool):
    """Whatweb technology detection"""
    name = "whatweb"
    category = ToolCategory.RECON
    binary_name = "whatweb"
    description = "Web technology fingerprinting"
    default_timeout = 500
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "whatweb"]
        additional = kwargs.get("additional_args", "-a 3")
        if additional:
            cmd.extend(shlex.split(additional))
        cmd.append(target)
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        technologies = []
        for line in output.split('\n'):
            if line.strip():
                # Parse whatweb output format
                parts = line.split('[')
                for part in parts[1:]:
                    if ']' in part:
                        tech = part.split(']')[0].strip()
                        if tech:
                            technologies.append(tech)
        return {
            "technologies": list(set(technologies)),
            "raw": output
        }


@register_tool
class NaabuTool(BaseTool):
    """Naabu fast port scanner"""
    name = "naabu"
    category = ToolCategory.SCANNER
    binary_name = "naabu"
    description = "Fast port scanner"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "naabu", "-host", target, "-silent"]
        
        ports = kwargs.get("ports", "")
        if ports:
            cmd.extend(["-p", ports])
        
        top_ports = kwargs.get("top_ports", 0)
        if top_ports:
            cmd.extend(["-top-ports", str(top_ports)])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        ports = []
        for line in output.split('\n'):
            line = line.strip()
            if line and ':' in line:
                parts = line.split(':')
                if len(parts) == 2:
                    ports.append({
                        "host": parts[0],
                        "port": parts[1]
                    })
        return {
            "ports": ports,
            "total": len(ports)
        }


@register_tool
class DalfoxTool(BaseTool):
    """Dalfox XSS scanner"""
    name = "dalfox"
    category = ToolCategory.SCANNER
    binary_name = "dalfox"
    description = "Advanced XSS scanner"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "dalfox", "-s", "url", target]
        
        param = kwargs.get("param", "")
        if param:
            cmd.extend(["-p", param])
        
        blind = kwargs.get("blind", "")
        if blind:
            cmd.extend(["--blind", blind])
        
        cookie = kwargs.get("cookie", "")
        if cookie:
            cmd.extend(["--cookie", cookie])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        vulnerabilities = []
        for line in output.split('\n'):
            if '[POC]' in line or '[V]' in line:
                vulnerabilities.append(line.strip())
        return {
            "vulnerabilities": vulnerabilities,
            "vulnerable": len(vulnerabilities) > 0,
            "raw": output
        }


@register_tool
class SqlmapTool(BaseTool):
    """Sqlmap SQL injection scanner"""
    name = "sqlmap"
    category = ToolCategory.SCANNER
    binary_name = "sqlmap"
    description = "Automatic SQL injection tool"
    default_timeout = 600
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "sqlmap", "-u", target, "--batch", "--disable-coloring"]
        
        data = kwargs.get("data", "")
        if data:
            cmd.extend(["--data", data])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        injectable = []
        dbms = None
        
        for line in output.split('\n'):
            if 'is vulnerable' in line.lower():
                injectable.append(line.strip())
            if 'back-end DBMS:' in line:
                dbms = line.split(':')[-1].strip()
        
        return {
            "injectable_params": injectable,
            "dbms": dbms,
            "vulnerable": len(injectable) > 0,
            "raw": output
        }


@register_tool
class GauTool(BaseTool):
    """Gau URL fetcher"""
    name = "gau"
    category = ToolCategory.RECON
    binary_name = "gau"
    description = "Fetch known URLs from AlienVault, Wayback, Common Crawl"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "gau"]
        
        providers = kwargs.get("providers", "")
        if providers:
            cmd.extend(["--providers", providers])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd

    def run(self, target: str, timeout: int = None, stdout_callback=None, stderr_callback=None, **kwargs) -> ToolResult:
        return super().run(target, timeout=timeout, stdin=target, stdout_callback=stdout_callback, stderr_callback=stderr_callback, **kwargs)
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        urls = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            "urls": urls,
            "total": len(urls)
        }


@register_tool
class WaybackurlsTool(BaseTool):
    """Waybackurls fetcher"""
    name = "waybackurls"
    category = ToolCategory.RECON
    binary_name = "waybackurls"
    description = "Fetch URLs from Wayback Machine"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "waybackurls"]
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd

    def run(self, target: str, timeout: int = None, stdout_callback=None, stderr_callback=None, **kwargs) -> ToolResult:
        return super().run(target, timeout=timeout, stdin=target, stdout_callback=stdout_callback, stderr_callback=stderr_callback, **kwargs)
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        urls = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            "urls": urls,
            "total": len(urls)
        }


@register_tool
class ArjunTool(BaseTool):
    """Arjun parameter discovery"""
    name = "arjun"
    category = ToolCategory.FUZZER
    binary_name = "arjun"
    description = "HTTP parameter discovery"
    default_timeout = 300
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_path or "arjun", "-s", "-u", target]
        
        method = kwargs.get("method", "GET")
        cmd.extend(["-m", method])
        
        wordlist = kwargs.get("wordlist", "")
        raw_wordlist = wordlist
        
        # Map common dirb paths to aliases for SecLists preference
        from config import SECLISTS_PATH
        dirb_to_alias = {
            "/usr/share/wordlists/dirb/common.txt": "common",
            "/usr/share/wordlists/dirb/big.txt": "big",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt": "dir_medium",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt": "dir_small",
            f"{SECLISTS_PATH}/Discovery/Web-Content/common.txt": "common",
            f"{SECLISTS_PATH}/Discovery/Web-Content/big.txt": "big",
            f"{SECLISTS_PATH}/Discovery/Web-Content/directory-list-2.3-medium.txt": "dir_medium",
            f"{SECLISTS_PATH}/Discovery/Web-Content/directory-list-2.3-small.txt": "dir_small",
        }
        if wordlist in dirb_to_alias:
            wordlist = dirb_to_alias[wordlist]
        
        if wordlist:
            try:
                if isinstance(wordlist, str) and wordlist and "/" not in wordlist and not wordlist.startswith(".") and "." not in wordlist:
                    from config import resolve_wordlist_path, WORDLISTS
                    if wordlist not in WORDLISTS:
                        raise ValueError(f"Unknown wordlist: {wordlist}")
                    wordlist = resolve_wordlist_path(wordlist)
            except Exception:
                pass
            if isinstance(wordlist, str) and wordlist and not os.path.exists(wordlist):
                raise ValueError(f"Wordlist not found: {raw_wordlist}")
            cmd.extend(["-w", wordlist])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(shlex.split(additional))
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        """
        Parse Arjun output to extract discovered parameters.
        
        Arjun output formats:
        - [+] Valid parameter found: param_name
        - Valid parameter found: param_name
        - JSON output: {"parameters": ["param1", "param2"]}
        """
        params = []
        
        # Try JSON parsing first (if -oJ flag was used)
        try:
            import json
            if output.strip().startswith('{'):
                data = json.loads(output)
                if "parameters" in data:
                    params = data["parameters"]
                    return {
                        "parameters": params,
                        "total": len(params)
                    }
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Parse text output
        for line in output.split('\n'):
            line = line.strip()
            
            # Match various Arjun output patterns
            if 'Valid parameter found:' in line or 'parameter found:' in line.lower():
                # Extract parameter name after colon
                parts = line.split(':')
                if len(parts) > 1:
                    param = parts[-1].strip()
                    if param and param not in params:
                        params.append(param)
            
            # Match [+] param_name format
            elif line.startswith('[+]') and 'parameter' not in line.lower():
                param = line.replace('[+]', '').strip()
                if param and param not in params:
                    params.append(param)
            
            # Match lines with just parameter names (after header)
            elif line and not line.startswith('[') and not line.startswith('Arjun'):
                # Simple heuristic: if it's a short alphanumeric string, might be a param
                if len(line) < 50 and line.replace('_', '').replace('-', '').isalnum():
                    if line not in params and line.lower() not in ['get', 'post', 'url', 'target']:
                        params.append(line)
        
        return {
            "parameters": params,
            "total": len(params)
        }


def run_tool(name: str, target: str, **kwargs) -> ToolResult:
    """
    Convenience function to run a tool by name.
    
    Usage:
        result = run_tool("nmap", "192.168.1.1", ports="80,443")
    """
    tool = get_tool(name)
    if not tool:
        return ToolResult(
            success=False,
            tool_name=name,
            error=f"Tool '{name}' not registered"
        )
    return tool.run(target, **kwargs)

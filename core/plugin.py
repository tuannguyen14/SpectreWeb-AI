"""
Plugin Architecture for Tools

Provides a standardized interface for security tools (nmap, ffuf, katana, etc.)
to enable easy integration and consistent behavior.
"""

import subprocess
import shutil
import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass, field
from enum import Enum


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
        """Get path to tool binary"""
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
        **kwargs
    ) -> ToolResult:
        """
        Execute the tool.
        
        Args:
            target: Primary target
            timeout: Execution timeout in seconds
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
            cmd = self.build_command(target, **kwargs)
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=f"Failed to build command: {e}"
            )
        
        # Execute
        timeout = timeout or self.default_timeout
        start_time = time.time()
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            duration = time.time() - start_time
            output = process.stdout + process.stderr
            
            # Parse output
            try:
                parsed = self.parse_output(output, process.returncode)
            except Exception as e:
                parsed = {"parse_error": str(e), "raw": output}
            
            return ToolResult(
                success=process.returncode == 0,
                tool_name=self.name,
                command=" ".join(cmd),
                output=output,
                parsed_data=parsed,
                duration_seconds=duration,
                exit_code=process.returncode
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=" ".join(cmd),
                error=f"Timeout after {timeout} seconds",
                duration_seconds=timeout
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=" ".join(cmd) if cmd else "",
                error=str(e),
                duration_seconds=time.time() - start_time
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
        cmd = ["nmap"]
        
        scan_type = kwargs.get("scan_type", "-sV")
        if scan_type:
            cmd.extend(scan_type.split())
        
        ports = kwargs.get("ports", "")
        if ports:
            cmd.extend(["-p", ports])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(additional.split())
        
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
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = ["ffuf", "-u", target]
        
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.extend(["-w", wordlist])
        
        match_codes = kwargs.get("match_codes", "200,301,302,403")
        cmd.extend(["-mc", match_codes])
        
        cmd.extend(["-o", "/dev/stdout", "-of", "json"])
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(additional.split())
        
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
        cmd = ["katana", "-u", target]
        
        depth = kwargs.get("depth", 2)
        cmd.extend(["-d", str(depth)])
        
        if kwargs.get("js_crawl", True):
            cmd.append("-jc")
        
        cmd.append("-silent")
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(additional.split())
        
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
        cmd = ["subfinder", "-d", target, "-silent"]
        
        additional = kwargs.get("additional_args", "")
        if additional:
            cmd.extend(additional.split())
        
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
        cmd = ["httpx", "-u", target]
        
        additional = kwargs.get("additional_args", "-status-code -title -tech-detect")
        if additional:
            cmd.extend(additional.split())
        
        return cmd
    
    def parse_output(self, output: str, exit_code: int) -> Dict:
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        return {
            "results": lines,
            "total": len(lines)
        }

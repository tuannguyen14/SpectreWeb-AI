"""Command Executor with Beautiful Real-time Output"""
import subprocess
import threading
import time
import logging
import sys
import re
from datetime import datetime
from typing import Dict, Any

from .cache import cache

logger = logging.getLogger(__name__)

# ANSI Colors for beautiful output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground
    RED = "\033[38;5;196m"
    GREEN = "\033[38;5;46m"
    YELLOW = "\033[38;5;226m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    CYAN = "\033[38;5;51m"
    ORANGE = "\033[38;5;208m"
    GRAY = "\033[38;5;245m"
    WHITE = "\033[38;5;255m"
    
    # Background
    BG_RED = "\033[48;5;196m"
    BG_GREEN = "\033[48;5;46m"
    BG_BLUE = "\033[48;5;39m"

def colorize(text: str, color: str, bold: bool = False) -> str:
    """Apply color to text"""
    prefix = Colors.BOLD if bold else ""
    return f"{prefix}{color}{text}{Colors.RESET}"

def format_bytes(size: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"

def create_box(title: str, content: list, color: str = Colors.CYAN) -> str:
    """Create a beautiful box for output"""
    width = 70
    lines = [
        f"{color}{'─' * width}{Colors.RESET}",
        f"{color}│{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}",
        f"{color}{'─' * width}{Colors.RESET}",
    ]
    for item in content:
        lines.append(f"{color}│{Colors.RESET} {item}")
    lines.append(f"{color}{'─' * width}{Colors.RESET}")
    return "\n".join(lines)


class CommandExecutor:
    """Execute shell commands with beautiful real-time output"""
    
    SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    PROGRESS_BAR_WIDTH = 30
    
    def __init__(self, command: str, timeout: int = 600, stdout_callback=None, stderr_callback=None):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.start_time = None
        self.bytes_received = 0
        self.lines_received = 0
        self.stdout_callback = stdout_callback
        self.stderr_callback = stderr_callback

    def _read_stdout(self):
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    self.bytes_received += len(line)
                    self.lines_received += 1
                    
                    if self.stdout_callback:
                        self.stdout_callback(line)
                        
                    # Beautiful output with line numbers
                    line_num = colorize(f"[{self.lines_received:4d}]", Colors.GRAY)
                    logger.info(f"  {line_num} {line.rstrip()}")
        except:
            pass

    def _read_stderr(self):
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    
                    if self.stderr_callback:
                        self.stderr_callback(line)
                        
                    err_prefix = colorize("ERR", Colors.RED, bold=True)
                    logger.warning(f"  [{err_prefix}] {line.rstrip()}")
        except:
            pass

    def _show_progress(self):
        start = time.time()
        i = 0
        last_bytes = 0
        last_lines = 0
        last_heartbeat = 0
        stall_count = 0
        
        while self.process and self.process.poll() is None:
            elapsed = time.time() - start
            spinner = self.SPINNER[i % len(self.SPINNER)]
            
            # Calculate speed
            speed = (self.bytes_received - last_bytes) / 0.5 if elapsed > 0 else 0
            lines_delta = self.lines_received - last_lines
            last_bytes = self.bytes_received
            last_lines = self.lines_received
            
            # Detect stall (no new output for 3 cycles = 1.5s)
            if lines_delta == 0 and self.bytes_received > 0:
                stall_count += 1
            else:
                stall_count = 0
            
            # Progress bar (based on time for unknown length)
            progress = min(elapsed / self.timeout, 0.99)
            filled = int(self.PROGRESS_BAR_WIDTH * progress)
            bar = colorize("█" * filled, Colors.GREEN) + colorize("░" * (self.PROGRESS_BAR_WIDTH - filled), Colors.GRAY)
            
            # Status indicator
            if stall_count >= 6:  # 3 seconds no output
                status_icon = colorize("⏳", Colors.YELLOW)
                status_text = "waiting..."
            elif speed > 0:
                status_icon = colorize("⚡", Colors.GREEN)
                status_text = f"{format_bytes(int(speed))}/s"
            else:
                status_icon = colorize(spinner, Colors.CYAN)
                status_text = "processing..."
            
            # Status line
            status = (
                f"  {status_icon} "
                f"[{bar}] "
                f"{colorize(f'{elapsed:.1f}s', Colors.YELLOW)} "
                f"│ {colorize(format_bytes(self.bytes_received), Colors.BLUE)} "
                f"│ {colorize(f'{self.lines_received} lines', Colors.MAGENTA)} "
                f"│ {status_text}"
            )
            
            # Print on same line (only in terminal)
            if elapsed > 1 and int(elapsed * 2) % 2 == 0:
                print(f"\r{status}", end="", flush=True, file=sys.stderr)
            
            # Heartbeat log every 10 seconds to show still running
            if elapsed - last_heartbeat >= 10:
                last_heartbeat = elapsed
                heartbeat_msg = f"  {colorize('💓', Colors.GREEN)} Still running... {colorize(f'{elapsed:.0f}s', Colors.YELLOW)} | {self.lines_received} lines received"
                if stall_count >= 6:
                    heartbeat_msg += f" | {colorize('(waiting for output)', Colors.YELLOW)}"
                logger.info(heartbeat_msg)
            
            time.sleep(0.5)
            i += 1
            
            if elapsed > self.timeout:
                break
        
        # Clear progress line
        print("\r" + " " * 100 + "\r", end="", file=sys.stderr)

    def execute(self) -> Dict[str, Any]:
        self.start_time = time.time()
        
        try:
            # Beautiful header
            cmd_preview = self.command[:80] + ('...' if len(self.command) > 80 else '')
            header = create_box(
                "🚀 EXECUTING COMMAND",
                [
                    f"{colorize('Command:', Colors.CYAN)} {cmd_preview}",
                    f"{colorize('Timeout:', Colors.CYAN)} {self.timeout}s",
                    f"{colorize('Time:', Colors.CYAN)} {datetime.now().strftime('%H:%M:%S')}",
                ],
                Colors.BLUE
            )
            logger.info(f"\n{header}")
            
            self.process = subprocess.Popen(
                self.command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
            
            pid_info = colorize(f"PID {self.process.pid}", Colors.MAGENTA, bold=True)
            logger.info(f"  {pid_info} started")
            logger.info(f"  {colorize('─' * 50, Colors.GRAY)}")
            
            # Start monitoring threads
            threads = [
                threading.Thread(target=self._read_stdout, daemon=True),
                threading.Thread(target=self._read_stderr, daemon=True),
                threading.Thread(target=self._show_progress, daemon=True),
            ]
            for t in threads:
                t.start()
            
            try:
                return_code = self.process.wait(timeout=self.timeout)
                threads[0].join(timeout=1)
                threads[1].join(timeout=1)
                
                execution_time = time.time() - self.start_time
                success = return_code == 0
                
                # Beautiful result box
                status_color = Colors.GREEN if success else Colors.RED
                status_icon = "✅ SUCCESS" if success else "❌ FAILED"
                
                result_box = create_box(
                    status_icon,
                    [
                        f"{colorize('Exit Code:', Colors.CYAN)} {return_code}",
                        f"{colorize('Duration:', Colors.CYAN)} {execution_time:.2f}s",
                        f"{colorize('Output:', Colors.CYAN)} {format_bytes(len(self.stdout_data))} ({self.lines_received} lines)",
                        f"{colorize('Errors:', Colors.CYAN)} {format_bytes(len(self.stderr_data))}",
                    ],
                    status_color
                )
                logger.info(f"\n{result_box}\n")
                
                # Combine output for tools that write to stderr (like httpx)
                combined_output = self.stdout_data
                if not combined_output.strip() and self.stderr_data.strip():
                    combined_output = self.stderr_data
                elif self.stdout_data.strip() and self.stderr_data.strip():
                    # If both have content, combine them
                    combined_output = self.stdout_data + self.stderr_data
                
                return {
                    "success": success,
                    "stdout": self.stdout_data,
                    "stderr": self.stderr_data,
                    "output": combined_output,  # Combined output for API consumers
                    "return_code": return_code,
                    "command": self.command,
                    "execution_time": execution_time,
                    "output_lines": self.lines_received,
                    "output_bytes": self.bytes_received,
                    "timestamp": datetime.now().isoformat()
                }
                
            except subprocess.TimeoutExpired:
                self.process.kill()
                timeout_box = create_box(
                    "⏰ TIMEOUT",
                    [f"Command killed after {self.timeout}s"],
                    Colors.ORANGE
                )
                logger.warning(f"\n{timeout_box}")
                # Combine output for timeout case too
                combined_output = self.stdout_data
                if not combined_output.strip() and self.stderr_data.strip():
                    combined_output = self.stderr_data
                
                return {
                    "success": False,
                    "error": f"Timeout after {self.timeout}s",
                    "stdout": self.stdout_data,
                    "stderr": self.stderr_data,
                    "output": combined_output,
                    "command": self.command
                }
                
        except Exception as e:
            error_box = create_box("💥 ERROR", [str(e)], Colors.RED)
            logger.error(f"\n{error_box}")
            return {"success": False, "error": str(e), "command": self.command, "output": ""}


def resolve_wordlist_in_command(command: str) -> str:
    """
    Resolve wordlist names in command to full paths.
    
    Supports:
    - ffuf -w wordlist_name
    - gobuster -w wordlist_name
    - wfuzz -w wordlist_name
    - Any tool with -w or --wordlist flag
    """
    try:
        from config import resolve_wordlist_path
        
        # Pattern to match -w wordlist_name or --wordlist wordlist_name
        # Matches: -w name, -w=name, --wordlist name, --wordlist=name
        patterns = [
            (r'-w\s+([^\s/]+)(?=\s|$)', r'-w \1'),  # -w name
            (r'-w=([^\s/]+)', r'-w=\1'),             # -w=name
            (r'--wordlist\s+([^\s/]+)(?=\s|$)', r'--wordlist \1'),  # --wordlist name
            (r'--wordlist=([^\s/]+)', r'--wordlist=\1'),            # --wordlist=name
        ]
        
        for pattern, template in patterns:
            matches = re.finditer(pattern, command)
            for match in matches:
                wordlist_name = match.group(1)
                # Only resolve if it doesn't look like a path
                if '/' not in wordlist_name and not wordlist_name.startswith('.'):
                    resolved_path = resolve_wordlist_path(wordlist_name)
                    if resolved_path != wordlist_name:
                        # Replace in command
                        old_part = match.group(0)
                        new_part = old_part.replace(wordlist_name, resolved_path)
                        command = command.replace(old_part, new_part)
                        logger.info(f"  📝 Resolved wordlist: {colorize(wordlist_name, Colors.YELLOW)} → {colorize(resolved_path, Colors.GREEN)}")
        
        return command
    except Exception as e:
        logger.debug(f"Wordlist resolution failed: {e}")
        return command


def execute_command(command: str, use_cache: bool = False) -> Dict[str, Any]:
    """Execute command with optional caching and wordlist resolution"""
    # Auto-resolve wordlist names to paths
    original_command = command
    command = resolve_wordlist_in_command(command)
    
    if use_cache:
        cached = cache.get(original_command)
        if cached:
            cached["from_cache"] = True
            return cached
    
    result = CommandExecutor(command).execute()
    
    if use_cache and result.get("success"):
        cache.set(original_command, {}, result)
    
    return result

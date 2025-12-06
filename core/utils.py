"""Utility functions for SpectreWeb"""

import re


def clean_projectdiscovery_output(text: str) -> str:
    """
    Clean output from ProjectDiscovery tools by removing ANSI codes and banners.
    
    This function handles common patterns in tools like:
    - httpx, nuclei, subfinder, katana, naabu, etc.
    
    Args:
        text: Raw output from ProjectDiscovery tool
        
    Returns:
        Cleaned text without ANSI codes and banners
    """
    if not text:
        return ""
    
    # Remove ANSI escape sequences (colors, formatting)
    clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    
    # Skip lines containing banner/info patterns
    skip_patterns = [
        'projectdiscovery.io',
        'Current httpx version',
        'Current nuclei version', 
        'Current subfinder version',
        'Current katana version',
        'Current naabu version',
        'UI Dashboard is disabled',
        '__    __  __',
        '/ /_  / /_/ /',
        '/ __ \\/ __/ __/',
        '/ / / / /_/ /_/',
        '/_/ /_/\\__/\\__/',
        '/_/',
        '[INF]',
        '[WRN]',
    ]
    
    lines = clean_text.split('\n')
    clean_lines = []
    
    for line in lines:
        line = line.strip()
        # Skip empty lines
        if not line:
            continue
        # Skip banner/info lines
        if any(pattern in line for pattern in skip_patterns):
            continue
        # Skip lines that are just special characters
        if re.match(r'^[\s_/\\|]+$', line):
            continue
        clean_lines.append(line)
    
    return '\n'.join(clean_lines)


def extract_urls_from_text(text: str) -> list:
    """
    Extract URLs from text using regex.
    
    Args:
        text: Text containing URLs
        
    Returns:
        List of URLs found in text
    """
    if not text:
        return []
    
    # URL regex pattern
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls


def extract_domains_from_text(text: str) -> list:
    """
    Extract domain names from text.
    
    Args:
        text: Text containing domains
        
    Returns:
        List of domains found in text
    """
    if not text:
        return []
    
    # Domain regex pattern (subdomains included)
    domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)'
    domains = re.findall(domain_pattern, text, re.IGNORECASE)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_domains = []
    for domain in domains:
        if domain not in seen:
            seen.add(domain)
            unique_domains.append(domain)
    
    return unique_domains


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human readable duration string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def safe_filename(filename: str) -> str:
    """
    Create a safe filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    if not filename:
        return "output"
    
    # Remove invalid characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    safe = safe.strip('. ')
    # Limit length
    if len(safe) > 100:
        safe = safe[:100]
    
    return safe or "output"


def parse_httpx_output(output: str) -> list:
    """
    Parse httpx output into structured data.
    
    Args:
        output: Raw httpx output
        
    Returns:
        List of dictionaries with URL info
    """
    if not output:
        return []
    
    results = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('['):
            continue
        
        # Parse format: https://example.com [200] [OK] [tech1,tech2]
        parts = line.split('] [')
        if len(parts) >= 2:
            url = parts[0].strip()
            status = parts[1].strip('[]')
            title = parts[2].strip('[]') if len(parts) > 2 else ""
            tech = parts[3].strip('[]') if len(parts) > 3 else ""
            
            results.append({
                'url': url,
                'status_code': int(status) if status.isdigit() else 0,
                'title': title,
                'technologies': [t.strip() for t in tech.split(',')] if tech else []
            })
    
    return results


def parse_nuclei_output(output: str) -> list:
    """
    Parse nuclei output into structured data.
    
    Args:
        output: Raw nuclei output
        
    Returns:
        List of vulnerability findings
    """
    if not output:
        return []
    
    findings = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or not line.startswith('['):
            continue
        
        # Parse nuclei format: [severity] [template-id] [url] vulnerability
        if '][' in line:
            parts = line.split('][')
            if len(parts) >= 3:
                severity = parts[0].strip('[]')
                template_id = parts[1].strip('[]')
                url_info = parts[2].strip('[]')
                vuln_info = ']'.join(parts[3:]).strip(']') if len(parts) > 3 else ""
                
                findings.append({
                    'severity': severity,
                    'template_id': template_id,
                    'url': url_info.split(']')[0] if ']' in url_info else url_info,
                    'vulnerability': vuln_info
                })
    
    return findings


def count_lines(text: str) -> int:
    """
    Count non-empty lines in text.
    
    Args:
        text: Text to count lines in
        
    Returns:
        Number of non-empty lines
    """
    if not text:
        return 0
    
    return len([line for line in text.split('\n') if line.strip()])


def truncate_text(text: str, max_length: int = 1000, suffix: str = "...") -> str:
    """
    Truncate text to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

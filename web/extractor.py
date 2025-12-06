"""Web Content Extraction"""
import re
from typing import List, Dict

def extract_links(html: str, base_url: str = "") -> List[str]:
    """Extract all links from HTML"""
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
    ]
    links = set()
    for pattern in patterns:
        links.update(re.findall(pattern, html, re.IGNORECASE))
    
    if base_url:
        normalized = set()
        for link in links:
            if link.startswith('http'):
                normalized.add(link)
            elif link.startswith('//'):
                normalized.add('https:' + link)
            elif link.startswith('/'):
                normalized.add(base_url.rstrip('/') + link)
            elif not link.startswith(('#', 'javascript:', 'mailto:')):
                normalized.add(base_url.rstrip('/') + '/' + link)
        return list(normalized)
    
    return list(links)

def extract_forms(html: str) -> List[Dict]:
    """Extract forms with inputs"""
    forms = []
    form_pattern = r'<form[^>]*>(.*?)</form>'
    
    for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        
        action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
        
        inputs = []
        for inp in re.finditer(r'<input[^>]*>', form_html, re.I):
            inp_html = inp.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', inp_html, re.I)
            inp_type = re.search(r'type=["\']([^"\']*)["\']', inp_html, re.I)
            value = re.search(r'value=["\']([^"\']*)["\']', inp_html, re.I)
            
            inputs.append({
                "name": name.group(1) if name else "",
                "type": inp_type.group(1) if inp_type else "text",
                "value": value.group(1) if value else ""
            })
        
        forms.append({
            "action": action.group(1) if action else "",
            "method": method.group(1).upper() if method else "GET",
            "inputs": inputs
        })
    
    return forms

def extract_comments(html: str) -> List[str]:
    """Extract HTML comments"""
    return re.findall(r'<!--(.*?)-->', html, re.DOTALL)

def extract_js_files(html: str, base_url: str = "") -> List[str]:
    """Extract JavaScript file URLs"""
    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    
    if base_url:
        normalized = []
        for js in js_files:
            if js.startswith('http'):
                normalized.append(js)
            elif js.startswith('//'):
                normalized.append('https:' + js)
            elif js.startswith('/'):
                normalized.append(base_url.rstrip('/') + js)
            else:
                normalized.append(base_url.rstrip('/') + '/' + js)
        return normalized
    
    return js_files

def extract_endpoints_from_js(js_content: str) -> List[str]:
    """Extract API endpoints from JavaScript"""
    patterns = [
        r'["\']/(api|v1|v2|graphql)/[^"\']*["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
    ]
    
    endpoints = set()
    for pattern in patterns:
        for match in re.findall(pattern, js_content, re.I):
            if isinstance(match, tuple):
                endpoints.add(match[0])
            else:
                endpoints.add(match)
    
    return list(filter(None, endpoints))

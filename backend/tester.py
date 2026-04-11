import aiohttp
import asyncio
import yaml
import glob
from typing import List, Dict, Any
from urllib.parse import urljoin
from backend.ml.predictor import predictor

async def execute_yaml_templates(session: aiohttp.ClientSession, url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    yaml_files = glob.glob("payloads/*.yaml")
    
    async def run_payload(action_url, input_name, payload, form_inputs, indicators, vuln_name, severity):
        data = {name: "dummy_data" for name in form_inputs}
        data[input_name] = payload
        try:
            async with session.post(action_url, data=data, timeout=10) as response:
                text_lower = (await response.text()).lower()
                
                # Check Indicators
                is_vulnerable = False
                if "REFLECTION" in indicators:
                    # Specific logic for Reflection attacks (like XSS)
                    if payload.lower() in text_lower:
                        is_vulnerable = True
                else:
                    if any(indicator.lower() in text_lower for indicator in indicators):
                        is_vulnerable = True
                        
                if is_vulnerable:
                    ml_data = predictor.predict_optimal_payload_type(input_name)
                    
                    # Boost confidence if the ML predicted this specific vulnerability class
                    is_match = (ml_data["predicted_type"].lower().strip() == vuln_name.lower().strip())
                    ml_confidence = ml_data["confidence_score"] if is_match else max(0, float(ml_data["confidence_score"]) - 50.0)
                    
                    return {
                        "url": action_url, "input": input_name, 
                        "payload": payload, "vulnerable": True, 
                        "type": vuln_name, "severity": severity,
                        "ml_confidence": round(ml_confidence, 2)
                    }
        except Exception:
            pass
        return None

    tasks = []
    # Parse templates and schedule tasks
    for file_path in yaml_files:
        with open(file_path, "r") as f:
            template = yaml.safe_load(f)
            
        vuln_name = template.get("name", "Unknown")
        severity = template.get("severity", "Medium")
        payloads = template.get("payloads", [])
        indicators = template.get("indicators", [])
        
        for form in forms:
            action_url = form.get("action", "")
            inputs = form.get("inputs", [])
            for payload in payloads:
                for input_name in inputs:
                    tasks.append(run_payload(action_url, input_name, payload, inputs, indicators, vuln_name, severity))

    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def test_open_redirect(session: aiohttp.ClientSession, url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Open Redirect is hardcoded due to `allow_redirects=True` behavior requirement
    payloads = ["http://evil.com", "//evil.com"]
    
    async def run_payload(action_url, input_name, payload, form_inputs):
        if "url" not in input_name.lower() and "redirect" not in input_name.lower() and "next" not in input_name.lower():
            return None
            
        data = {name: "dummy_data" for name in form_inputs}
        data[input_name] = payload
        try:
            async with session.post(action_url, data=data, timeout=10, allow_redirects=True) as response:
                if str(response.url).startswith("http://evil.com"):
                    return {
                        "url": action_url, "input": input_name, 
                        "payload": payload, "vulnerable": True, 
                        "type": "Open Redirect", "severity": "Medium"
                    }
        except Exception:
            pass
        return None

    tasks = []
    for form in forms:
        action_url = form.get("action", "")
        inputs = form.get("inputs", [])
        for payload in payloads:
            for input_name in inputs:
                tasks.append(run_payload(action_url, input_name, payload, inputs))
                
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


def test_security_headers(url: str, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not headers.get("Content-Security-Policy"):
        findings.append({"url": url, "input": "HTTP Header", "payload": "Missing CSP", "vulnerable": True, "type": "Missing Security Header: CSP", "severity": "Low"})
    if not headers.get("Strict-Transport-Security") and url.startswith("https"):
        findings.append({"url": url, "input": "HTTP Header", "payload": "Missing HSTS", "vulnerable": True, "type": "Missing Security Header: HSTS", "severity": "Medium"})
    if not headers.get("X-Frame-Options"):
        findings.append({"url": url, "input": "HTTP Header", "payload": "Missing X-Frame-Options", "vulnerable": True, "type": "Missing Security Header: Clickjacking", "severity": "Medium"})
    return findings


def test_csrf(url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for form in forms:
        if not form.get("has_csrf_token"):
            findings.append({"url": form.get("action", ""), "input": "HTML Form", "payload": "Missing Anti-CSRF Token", "vulnerable": True, "type": "Missing CSRF Protection", "severity": "High"})
    return findings

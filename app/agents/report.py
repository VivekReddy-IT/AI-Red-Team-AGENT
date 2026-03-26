import os
from typing import Any

import requests
from pydantic import BaseModel, Field, ValidationError

from app.utils.parsers import parse_nmap_ports, parse_sqlmap_findings
from app.utils.risk import classify_severity


def _ollama_generate(prompt: str) -> str | None:
    """
    Try to generate text via local Ollama.
    Returns None if Ollama is unreachable.
    """
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "llama3")

    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                # Ask Ollama to return a valid JSON object.
                "format": "json",
                # Make the output deterministic to help strict JSON parsing.
                "options": {"temperature": 0},
                "num_predict": 256,
            },
            timeout=60,
        )
        resp.raise_for_status()
        data: Any = resp.json()
        return str(data.get("response") or "")
    except Exception:
        return None


class ReportFinding(BaseModel):
    title: str
    evidence: str
    severity: str = Field(..., description="Low/Medium/High")
    remediation: str


class SecurityReport(BaseModel):
    title: str
    severity: str = Field(..., description="Low/Medium/High")
    executive_summary: str
    findings: list[ReportFinding]
    recommended_next_steps: list[str]


def _normalize_severity(v: str) -> str:
    s = (v or "").upper()
    if s == "HIGH":
        return "High"
    if s == "MEDIUM":
        return "Medium"
    return "Low"


def _extract_json_object(text: str) -> str | None:
    """
    Robustly extract the first JSON object from an LLM response.
    Handles cases like: ```json { ... } ``` or extra whitespace.
    """
    if not text:
        return None

    import json as _json

    # Find the first '{' and attempt to decode exactly one JSON object from there.
    start = text.find("{")
    if start == -1:
        return None

    decoder = _json.JSONDecoder()
    try:
        obj, idx = decoder.raw_decode(text[start:])
        return _json.dumps(obj)
    except Exception:
        return None


def _coerce_next_steps(v: Any) -> list[str]:
    if isinstance(v, list):
        out: list[str] = []
        for x in v:
            if isinstance(x, str):
                out.append(x)
        return out
    if isinstance(v, str):
        # Split on common separators to recover a list-ish string.
        parts = [p.strip() for p in v.replace("\r", "\n").split("\n") if p.strip()]
        return parts[:10]
    return []


def _coerce_findings(v: Any, heuristic_severity: str) -> list[dict[str, str]]:
    if not isinstance(v, list):
        return []
    out: list[dict[str, str]] = []
    for item in v:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("name") or "Finding")
        evidence = str(
            item.get("evidence")
            or item.get("evidence_text")
            or item.get("description")
            or "Detected in scan output"
        )
        remediation = str(
            item.get("remediation")
            or item.get("fix")
            or item.get("recommendation")
            or "Verify and remediate per secure configuration and vendor guidance."
        )
        sev_raw = item.get("severity") or heuristic_severity
        severity = _normalize_severity(str(sev_raw))
        out.append(
            {
                "title": title,
                "evidence": evidence,
                "severity": severity,
                "remediation": remediation,
            }
        )
    return out


def _ollama_generate_report_json(
    prompt: str, heuristic_severity: str
) -> dict[str, Any] | None:
    """
    Call Ollama and return validated JSON report dict.
    """
    ai_text = _ollama_generate(prompt)
    if not ai_text:
        return None

    import json

    raw_obj = _extract_json_object(ai_text)
    if not raw_obj:
        return None

    try:
        parsed = json.loads(raw_obj)
    except Exception:
        return None

    try:
        title = str(parsed.get("title") or "Security Scan Results (Automated)")
        exec_summary = str(
            parsed.get("executive_summary")
            or parsed.get("executiveSummary")
            or parsed.get("summary")
            or "Automated recon and checks completed under safe mode."
        )

        severity = _normalize_severity(str(parsed.get("severity") or heuristic_severity))
        findings = _coerce_findings(parsed.get("findings"), heuristic_severity)
        recommended_next_steps = _coerce_next_steps(
            parsed.get("recommended_next_steps")
            or parsed.get("recommendedNextSteps")
            or parsed.get("next_steps")
            or parsed.get("nextSteps")
        )

        report = SecurityReport(
            title=title,
            severity=severity,
            executive_summary=exec_summary,
            findings=[ReportFinding(**f) for f in findings],
            recommended_next_steps=recommended_next_steps
            if recommended_next_steps
            else [
                "Manually verify detected services and configuration.",
                "If SQL injection is suspected, review input handling and use parameterized queries.",
                "Add WAF rules and validate with OWASP ZAP in safe test scope.",
            ],
        ).model_dump()

        return report
    except Exception:
        return None


def generate_ai_report(
    scan_data: str, zap_findings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """
    Convert raw scan output into a strict JSON security report.
    If `zap_findings` are provided, they are included in the report.
    """
    zap_findings = zap_findings or []

    heuristic_severity = classify_severity(scan_data)
    severity = _normalize_severity(heuristic_severity)
    ports = parse_nmap_ports(scan_data)
    sql_findings = parse_sqlmap_findings(scan_data)

    findings: list[dict[str, Any]] = []

    for p in ports:
        if p.get("state") == "open":
            findings.append(
                {
                    "type": "open_service",
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service"),
                    "version": p.get("version"),
                    "severity": "LOW",
                    "title": p.get("service") or "open_service",
                }
            )

    for f in sql_findings:
        findings.append(
            {
                "type": f.get("type") or "finding",
                **{k: v for k, v in f.items() if k != "type"},
                "severity": heuristic_severity,
                "title": f.get("type") or "sql_injection",
            }
        )

    # Add ZAP findings and override severity if ZAP is more severe.
    zap_priority = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    max_zap_sev: str | None = None
    for z in zap_findings:
        if not isinstance(z, dict):
            continue
        z_sev = str(z.get("severity") or "LOW").upper()
        if max_zap_sev is None or zap_priority.get(z_sev, 1) > zap_priority.get(max_zap_sev, 1):
            max_zap_sev = z_sev

        findings.append(
            {
                "type": z.get("type") or "zap_alert",
                "title": z.get("title") or "ZAP Alert",
                "evidence": z.get("evidence") or "Detected by ZAP",
                "severity": z_sev if z_sev in ("LOW", "MEDIUM", "HIGH") else "LOW",
                "confidence": z.get("confidence"),
            }
        )

    if max_zap_sev:
        heuristic_severity = max_zap_sev
        severity = _normalize_severity(heuristic_severity)

    detected_facts = {
        "parsed_ports": ports,
        "parsed_sqlmap_findings": sql_findings,
        "zap_findings": zap_findings[:30],
        "heuristic_severity": heuristic_severity,
        "detected_finding_types": [f.get("type") for f in findings],
    }

    # Reliability + speed gate:
    # When severity is LOW, return heuristic strict JSON immediately.
    if heuristic_severity == "LOW":
        title = "Security Scan Results (Automated)"
        exec_summary = (
            "Automated recon and checks completed under safe mode. "
            f"Overall heuristic severity is {severity}. "
            "Review findings below and validate in a controlled test environment."
        )

        report_findings: list[dict[str, Any]] = []
        for f in findings[:20]:
            report_findings.append(
                {
                    "title": f.get("title") or f.get("type", "Finding"),
                    "evidence": f.get("evidence") or f.get("service") or f.get("parameter") or "Detected in scan output",
                    "severity": _normalize_severity(str(f.get("severity", heuristic_severity))),
                    "remediation": "Verify and remediate per secure configuration and vendor guidance.",
                }
            )

        fallback_report = SecurityReport(
            title=title,
            severity=severity,
            executive_summary=exec_summary,
            findings=[ReportFinding(**x) for x in report_findings],
            recommended_next_steps=[
                "Manually verify detected services and configuration.",
                "If SQL injection is suspected, review input handling and use parameterized queries.",
                "Add WAF rules and validate with OWASP ZAP in safe test scope.",
            ],
        ).model_dump()

        # Extra artifacts for dashboard/JSON consumers.
        fallback_report["parsed_ports"] = ports
        fallback_report["parsed_sqlmap_findings"] = sql_findings
        fallback_report["parsed_zap_findings"] = zap_findings
        fallback_report["report_source"] = "heuristic_low"
        return fallback_report

    prompt = f"""
You are a cybersecurity analyst. Produce a professional security report for an ethical test.

Input raw scan output:
{scan_data}

You also have these detected facts (JSON):
{detected_facts}

Return ONLY a valid JSON object (no markdown, no backticks, no extra text).

Schema (exact keys):
{{
  "title": "string",
  "severity": "Low|Medium|High",
  "executive_summary": "string",
  "findings": [
    {{
      "title": "string",
      "evidence": "string",
      "severity": "Low|Medium|High",
      "remediation": "string"
    }}
  ],
  "recommended_next_steps": ["string"]
}}

Constraints:
- Do not claim exploitation.
- If the input does not show a clear vulnerability, state that clearly in "executive_summary".
- Keep it concise but professional.
"""

    parsed_report = _ollama_generate_report_json(prompt, heuristic_severity)
    if parsed_report:
        parsed_report["severity"] = _normalize_severity(parsed_report.get("severity", severity))
        for f in parsed_report.get("findings", []):
            if isinstance(f, dict) and "severity" in f:
                f["severity"] = _normalize_severity(f.get("severity", "LOW"))
        parsed_report["report_source"] = "ollama"
        return parsed_report

    # Fallback strict JSON if Ollama is not available / unparseable.
    title = "Security Scan Results (Automated)"
    exec_summary = (
        "Automated recon and checks completed under safe mode. "
        f"Overall heuristic severity is {severity}. "
        "Review findings below and validate in a controlled test environment."
    )

    report_findings: list[dict[str, Any]] = []
    for f in findings[:20]:
        report_findings.append(
            {
                "title": f.get("title") or f.get("type", "Finding"),
                "evidence": f.get("evidence") or f.get("service") or f.get("parameter") or "Detected in scan output",
                "severity": _normalize_severity(str(f.get("severity", heuristic_severity))),
                "remediation": "Verify and remediate per secure configuration and vendor guidance.",
            }
        )

    recommended_next_steps = [
        "Manually verify detected services and configuration.",
        "If SQL injection is suspected, review input handling and use parameterized queries.",
        "Add WAF rules and validate with OWASP ZAP in safe test scope.",
    ]

    fallback_report = SecurityReport(
        title=title,
        severity=severity,
        executive_summary=exec_summary,
        findings=[ReportFinding(**x) for x in report_findings],
        recommended_next_steps=recommended_next_steps,
    ).model_dump()

    fallback_report["parsed_ports"] = ports
    fallback_report["parsed_sqlmap_findings"] = sql_findings
    fallback_report["parsed_zap_findings"] = zap_findings
    fallback_report["report_source"] = "fallback"
    return fallback_report


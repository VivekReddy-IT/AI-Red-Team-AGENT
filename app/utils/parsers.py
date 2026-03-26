import re
from typing import Any


_NMAP_LINE_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<proto>tcp|udp)\s+(?P<state>open|filtered)\s+(?P<service>[^ ]+)(?:\s+(?P<version>.+))?$",
    re.IGNORECASE,
)


def parse_nmap_ports(nmap_text: str) -> list[dict[str, Any]]:
    """
    Extract basic open/filtered ports from nmap -sV output.
    """
    ports: list[dict[str, Any]] = []
    for line in nmap_text.splitlines():
        line = line.strip()
        m = _NMAP_LINE_RE.match(line)
        if not m:
            continue
        ports.append(
            {
                "port": int(m.group("port")),
                "protocol": m.group("proto").lower(),
                "state": m.group("state").lower(),
                "service": (m.group("service") or "").strip(),
                "version": (m.group("version") or "").strip() if m.group("version") else None,
            }
        )
    return ports


def parse_sqlmap_findings(sqlmap_text: str) -> list[dict[str, Any]]:
    """
    Very lightweight parsing of common sqlmap indicators.
    """
    findings: list[dict[str, Any]] = []

    # Common phrases:
    # "Parameter 'id' is vulnerable."
    vuln_re = re.compile(
        r"Parameter\s+'(?P<param>[^']+)'\s+is\s+vulnerable(?:\s+to\s+'(?P<vector>[^']+)')?\.",
        re.IGNORECASE,
    )
    for m in vuln_re.finditer(sqlmap_text):
        findings.append(
            {
                "type": "sql_injection",
                "parameter": m.group("param"),
                "vector": m.group("vector"),
            }
        )

    # Another common phrase: "is vulnerable"
    if not findings and "is vulnerable" in sqlmap_text.lower():
        findings.append(
            {
                "type": "sql_injection",
                "detail": "sqlmap reported possible SQL injection (details not parsed).",
            }
        )

    return findings


def parse_zap_json(zap_json_text: str, allowed_host: str | None = None) -> list[dict[str, Any]]:
    """
    Parse ZAP baseline JSON output into a small list of findings.

    ZAP JSON structure can vary between versions, so this parser is defensive.
    """
    try:
        import json

        data = json.loads(zap_json_text or "{}")
    except Exception:
        return []

    alerts = data.get("alerts") or []
    if not isinstance(alerts, list):
        return []

    findings: list[dict[str, Any]] = []

    allowed = (allowed_host or "").lower().strip()

    for a in alerts:
        if not isinstance(a, dict):
            continue
        alert_name = str(a.get("alert") or a.get("name") or "ZAP Alert")
        risk = str(a.get("risk") or "Low")
        confidence = a.get("confidence")
        description = str(a.get("description") or a.get("desc") or "")

        # Pick evidence URI if present.
        evidence = ""
        instances = a.get("instances")
        if isinstance(instances, list) and instances:
            first = instances[0]
            if isinstance(first, dict):
                evidence = str(first.get("uri") or first.get("url") or "")

        # Filter out-of-scope evidence if allowed_host is given.
        if allowed and evidence:
            ev_host = (re.sub(r"^https?://", "", evidence)).split("/")[0].lower()
            if ev_host and ev_host != allowed:
                continue

        severity = "LOW"
        r = risk.lower()
        if "high" in r:
            severity = "HIGH"
        elif "medium" in r:
            severity = "MEDIUM"
        elif "low" in r:
            severity = "LOW"

        findings.append(
            {
                "type": "zap_alert",
                "title": alert_name,
                "evidence": evidence or (description[:120] if description else "Detected by ZAP"),
                "severity": severity,
                "confidence": confidence,
            }
        )

    return findings


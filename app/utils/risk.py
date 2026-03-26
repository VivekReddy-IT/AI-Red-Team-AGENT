from __future__ import annotations


def classify_severity(scan_text: str) -> str:
    """
    Heuristic severity classifier based on scan output keywords.
    """
    t = (scan_text or "").lower()

    # Heuristic markers for real vuln evidence (not just tool errors).
    if "vulnerable" in t and ("sql injection" in t or "sql-injection" in t):
        return "HIGH"

    # sqlmap often says "is vulnerable" / "sql injection"
    if "is vulnerable" in t and ("sql injection" in t or "sql-injection" in t):
        return "HIGH"

    if "is vulnerable" in t or "sql injection" in t or "sql-injection" in t:
        return "MEDIUM"

    # nmap output alone: treat as low (recon only)
    return "LOW"


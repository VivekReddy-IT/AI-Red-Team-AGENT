import asyncio
import json
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.agents.recon import run_nmap
from app.agents.exploit import run_sqlmap
from app.agents.report import generate_ai_report
from app.agents.http_probe import probe_http
from app.agents.zap import run_zap_baseline
from app.utils.parsers import parse_nmap_ports
from app.utils.safety import validate_target_safe_mode
from app.utils.storage import list_scans, load_scan, save_scan


app = FastAPI(title="AI Red Team Agent (Safe Mode)")


class ScanRequest(BaseModel):
    target: str


# In-memory job status; durable results are in app/results/*.json
JOBS: dict[str, dict[str, Any]] = {}


def _coerce_text(v: Any) -> str:
    """
    subprocess stdout/stderr can occasionally come back as bytes; normalize to str.
    """
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", errors="replace")
    return str(v)


def _risk_score_from_severity(severity: str) -> int:
    s = (severity or "").upper()
    if s == "HIGH":
        return 90
    if s == "MEDIUM":
        return 50
    return 10


def _job_summary(payload: dict[str, Any]) -> dict[str, Any]:
    ai = payload.get("ai_report") or {}
    severity = ai.get("severity") or payload.get("severity") or "LOW"
    return {
        "scan_id": payload.get("scan_id"),
        "target": payload.get("target"),
        "created_at": payload.get("created_at"),
        "status": payload.get("status"),
        "severity": severity,
        "risk_score": _risk_score_from_severity(severity),
    }


async def _run_scan_job(scan_id: str, target: str) -> None:
    start = time.time()
    safe, safe_host_or_msg = validate_target_safe_mode(target)
    if not safe:
        JOBS[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "status": "rejected",
            "reason": safe_host_or_msg,
            "created_at": time.time(),
        }
        # Still persist a record for history.
        save_scan(
            scan_id,
            {
                "scan_id": scan_id,
                "target": target,
                "created_at": time.time(),
                "status": "rejected",
                "reason": safe_host_or_msg,
                "recon": None,
                "exploit": None,
                "ai_report": None,
            },
        )
        return

    JOBS[scan_id] = {"scan_id": scan_id, "target": target, "status": "running", "created_at": time.time()}

        # nmap expects a host/IP; sqlmap/ZAP expect full URLs.
    nmap_target = safe_host_or_msg
    sqlmap_url = target if "://" in target else f"http://{target}"

    # Run blocking subprocesses in threads
    try:
        recon_task = asyncio.to_thread(run_nmap, nmap_target)
        probe_task = asyncio.to_thread(probe_http, sqlmap_url)
        recon_res, probe_res = await asyncio.gather(recon_task, probe_task)

        recon_text = _coerce_text(getattr(recon_res, "stdout", recon_res))
        recon_err = _coerce_text(getattr(recon_res, "stderr", ""))

        exploit_text = ""
        exploit_err = ""
        exploit_ok = None
        exploit_exit_code = None
        exploit_skipped_reason = None
        zap_stdout = ""
        zap_stderr = ""
        zap_ok = None
        zap_exit_code = None
        zap_findings: list[dict[str, Any]] = []

        # Decide whether to run ZAP:
        # - primary: HTTP probe says reachable
        # - fallback: nmap indicates HTTP(S) ports are open (80/443)
        parsed_ports = parse_nmap_ports(recon_text or "")
        has_http = any(p.get("port") == 80 and p.get("state") == "open" for p in parsed_ports)
        has_https = any(p.get("port") == 443 and p.get("state") == "open" for p in parsed_ports)

        # If we're scanning an approved non-local test host, attempt ZAP even if
        # nmap didn't detect HTTP(S) ports reliably in this run.
        is_loopback_host = safe_host_or_msg in {"localhost", "127.0.0.1", "::1"}
        want_zap = bool(probe_res.get("reachable")) or has_http or has_https or not is_loopback_host
        zap_url = sqlmap_url
        if "://" not in target:
            scheme = "https" if has_https else "http"
            zap_url = f"{scheme}://{target}"

        if want_zap:
            zap_res = await asyncio.to_thread(
                run_zap_baseline,
                zap_url,
                120,
                1,
                safe_host_or_msg,
            )
            zap_stdout = _coerce_text(getattr(zap_res, "stdout", ""))
            zap_stderr = _coerce_text(getattr(zap_res, "stderr", ""))
            zap_ok = getattr(zap_res, "ok", None)
            zap_exit_code = getattr(zap_res, "exit_code", None)
            zap_findings = getattr(zap_res, "findings", None) or []

        if probe_res.get("reachable"):
            exploit_res = await asyncio.to_thread(run_sqlmap, sqlmap_url)
            exploit_text = _coerce_text(getattr(exploit_res, "stdout", exploit_res))
            exploit_err = _coerce_text(getattr(exploit_res, "stderr", ""))
            exploit_ok = getattr(exploit_res, "ok", None)
            exploit_exit_code = getattr(exploit_res, "exit_code", None)
        else:
            exploit_skipped_reason = probe_res.get("reason") or "HTTP probe failed"

        combined = (recon_text or "") + "\n" + (exploit_text or "")

        # Ollama call is synchronous (requests) and can block; run in a thread.
        ai_report = await asyncio.to_thread(generate_ai_report, combined, zap_findings)
        severity = ai_report.get("severity") or "LOW"

        payload = {
            "scan_id": scan_id,
            "target": target,
            "safe_mode": True,
            "safe_host": safe_host_or_msg,
            "created_at": time.time(),
            "status": "completed",
            "runtime_seconds": round(time.time() - start, 2),
            "recon": recon_text,
            "recon_stderr": recon_err,
            "recon_ok": getattr(recon_res, "ok", None),
            "recon_exit_code": getattr(recon_res, "exit_code", None),
            "http_probe": probe_res,
            "exploit": exploit_text,
            "exploit_stderr": exploit_err,
            "exploit_ok": exploit_ok,
            "exploit_exit_code": exploit_exit_code,
            "exploit_skipped_reason": exploit_skipped_reason,
            "zap_stdout": zap_stdout,
            "zap_stderr": zap_stderr,
            "zap_ok": zap_ok,
            "zap_exit_code": zap_exit_code,
            "zap_findings": zap_findings,
            "ai_report": ai_report,
            "severity": severity,
        }

        save_scan(scan_id, payload)
        JOBS[scan_id] = payload
    except Exception as e:
        payload = {
            "scan_id": scan_id,
            "target": target,
            "safe_mode": True,
            "created_at": time.time(),
            "status": "failed",
            "error": str(e),
        }
        save_scan(scan_id, payload)
        JOBS[scan_id] = payload


@app.get("/")
def home() -> dict[str, str]:
    return {"message": "AI Red Team Agent Running (safe mode enabled)"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan(req: ScanRequest) -> dict[str, Any]:
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    scan_id = str(uuid.uuid4())
    JOBS[scan_id] = {"scan_id": scan_id, "target": target, "status": "queued", "created_at": time.time()}

    asyncio.create_task(_run_scan_job(scan_id, target))
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scan")
async def scan_get(target: str) -> dict[str, Any]:
    return await scan(ScanRequest(target=target))


@app.get("/scan/{scan_id}")
async def scan_status(scan_id: str) -> dict[str, Any]:
    if scan_id in JOBS:
        return {"job": JOBS[scan_id]}

    saved = load_scan(scan_id)
    if not saved:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"job": saved}


@app.get("/scans")
def scans() -> dict[str, Any]:
    saved = list_scans(limit=50)
    return {"scans": [_job_summary(s) for s in saved]}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    saved = list_scans(limit=50)
    items = []
    for s in saved:
        summary = _job_summary(s)
        sev = summary["severity"]
        items.append(
            f"<tr><td>{summary['created_at']:.0f}</td><td>{summary['target']}</td><td>{sev}</td><td>{summary['risk_score']}</td><td>{summary['scan_id']}</td></tr>"
        )

    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>AI Red Team Dashboard</title>
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }}
          table {{ border-collapse: collapse; width: 100%; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; }}
          th {{ background: #f6f6f6; }}
          code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 4px; }}
        </style>
      </head>
      <body>
        <h1>AI Red Team Dashboard (Safe Mode)</h1>
        <p>POST <code>/scan</code> with JSON: <code>{{"target":"testphp.vulnweb.com/..."}}</code></p>
        <table>
          <thead>
            <tr><th>Created</th><th>Target</th><th>Severity</th><th>Risk Score</th><th>Scan ID</th></tr>
          </thead>
          <tbody>
            {''.join(items) if items else '<tr><td colspan="5">No scans yet.</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
    """.strip()
    return HTMLResponse(html)


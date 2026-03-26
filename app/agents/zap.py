import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

from app.utils.parsers import parse_zap_json


@dataclass
class ZAPResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int | None = None
    findings: list[dict[str, Any]] | None = None


def _find_zap_baseline_py() -> str | None:
    candidates = [
        shutil.which("zap-baseline.py"),
        "/snap/bin/zap-baseline.py",
        "/snap/zaproxy/current/zap-baseline.py",
        "/snap/zaproxy/current/usr/share/zap/zap-baseline.py",
        "/snap/zaproxy/current/bin/zap-baseline.py",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def run_zap_baseline(
    target_url: str,
    timeout_s: int = 120,
    spider_mins: int = 1,
    allowed_host: str | None = None,
) -> ZAPResult:
    """
    OWASP ZAP baseline scan (passive + spider, non-intrusive).
    Output is parsed from ZAP JSON if available.
    """
    zap_baseline = _find_zap_baseline_py()
    if not zap_baseline:
        # Fallback: run baseline inside official ZAP Docker image (no host zap install needed).
        docker_bin = shutil.which("docker")
        if docker_bin:
            with tempfile.TemporaryDirectory(prefix="zapscan_") as td:
                json_path = os.path.join(td, "zap_baseline_report.json")
                html_path = os.path.join(td, "zap_baseline_report.html")

                # Container mounts td as /zap/wrk.
                docker_cmd = [
                    docker_bin,
                    "run",
                    "--rm",
                    "-v",
                    f"{td}:/zap/wrk/:rw",
                    "ghcr.io/zaproxy/zaproxy:stable",
                    "zap-baseline.py",
                    "-t",
                    target_url,
                    "-m",
                    str(spider_mins),
                    "-J",
                    "/zap/wrk/zap_baseline_report.json",
                    "-r",
                    "/zap/wrk/zap_baseline_report.html",
                    "-s",
                ]

                try:
                    proc = subprocess.run(
                        docker_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout_s,
                        check=False,
                        env={**os.environ, "LC_ALL": "C"},
                    )
                    stdout = proc.stdout or ""
                    stderr = proc.stderr or ""

                    findings: list[dict[str, Any]] = []
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, "r", encoding="utf-8") as f:
                                zap_json_text = f.read()
                            findings = parse_zap_json(
                                zap_json_text, allowed_host=allowed_host
                            )
                        except Exception:
                            findings = []

                    return ZAPResult(
                        ok=(proc.returncode == 0),
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=proc.returncode,
                        findings=findings,
                    )
                except subprocess.TimeoutExpired as e:
                    out = (e.stdout or "") if hasattr(e, "stdout") else ""
                    err = (e.stderr or "") if hasattr(e, "stderr") else ""
                    return ZAPResult(
                        ok=False,
                        stdout=out,
                        stderr=err or "zap baseline timeout",
                        exit_code=None,
                        findings=[],
                    )
                except Exception as e:
                    return ZAPResult(
                        ok=False,
                        stdout="",
                        stderr=str(e),
                        exit_code=None,
                        findings=[],
                    )

        return ZAPResult(
            ok=False,
            stdout="",
            stderr=(
                "zap-baseline.py not found. Either: "
                "1) install ZAP via snap (sudo snap install zaproxy --classic), or "
                "2) install Docker and re-run (ZAP will use the Docker fallback)."
            ),
            exit_code=None,
            findings=[],
        )

    with tempfile.TemporaryDirectory(prefix="zapscan_") as td:
        json_path = os.path.join(td, "zap_baseline_report.json")
        html_path = os.path.join(td, "zap_baseline_report.html")

        cmd = [
            zap_baseline,
            "-t",
            target_url,
            "-m",
            str(spider_mins),
            "-J",
            json_path,
            "-r",
            html_path,
            "-s",  # short output to keep logs manageable
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            findings: list[dict[str, Any]] = []
            if os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        zap_json_text = f.read()
                    findings = parse_zap_json(zap_json_text, allowed_host=allowed_host)
                except Exception:
                    findings = []

            return ZAPResult(
                ok=(proc.returncode == 0),
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode,
                findings=findings,
            )
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if hasattr(e, "stdout") else ""
            err = (e.stderr or "") if hasattr(e, "stderr") else ""
            return ZAPResult(
                ok=False,
                stdout=out,
                stderr=err or "zap baseline timeout",
                exit_code=None,
                findings=[],
            )
        except Exception as e:
            return ZAPResult(ok=False, stdout="", stderr=str(e), exit_code=None, findings=[])


import os
import subprocess
from dataclasses import dataclass
import shutil


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int | None = None


def run_nmap(target: str, timeout_s: int = 45) -> CommandResult:
    """
    Recon agent: run nmap service/version scan against the target host.

    NOTE: This agent is intended for safe/approved targets only.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return CommandResult(
            ok=False,
            stdout="",
            stderr="nmap not found on PATH. Install it (Ubuntu): sudo apt install nmap",
            exit_code=None,
        )

    # Use TCP connect scan (-sT) to avoid requiring elevated privileges.
    cmd = [nmap_bin, "-sV", "-sT", "-Pn", "--open", target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        return CommandResult(
            ok=(proc.returncode == 0),
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            exit_code=proc.returncode,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if hasattr(e, "stdout") else ""
        err = (e.stderr or "") if hasattr(e, "stderr") else ""
        return CommandResult(ok=False, stdout=out, stderr=err or "nmap timeout")
    except Exception as e:
        return CommandResult(ok=False, stdout="", stderr=str(e))


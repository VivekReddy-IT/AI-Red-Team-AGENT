import requests


def probe_http(url: str, timeout_s: int = 8) -> dict:
    """
    Lightweight reachability check for the URL.

    Purpose: avoid running long sqlmap attempts when the target is not
    reachable from this host/network.
    """
    headers = {"User-Agent": "Mozilla/5.0 (compatible; AI-RedTeam-Agent/1.0)"}
    try:
        # No redirects: keep the probe in-scope and avoid following to
        # an unapproved domain.
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout_s,
            allow_redirects=False,
            stream=True,
        )
        content_type = resp.headers.get("content-type")
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "content_type": content_type,
            "reason": "",
            "final_url": getattr(resp, "url", url),
        }
    except requests.exceptions.RequestException as e:
        return {
            "reachable": False,
            "status_code": None,
            "content_type": None,
            "reason": str(e),
            "final_url": None,
        }


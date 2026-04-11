import aiohttp
import asyncio
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse

async def crawl(url: str, max_depth: int = 1, cookie: str = None) -> Dict[str, Any]:
    """
    Crawls a given URL and its internal links asynchronously up to `max_depth`.
    Returns a dictionary of:
    {
      "forms": [{"action": "/login", "inputs": ["username", "password"], "has_csrf_token": True}],
      "security_headers": {...}
    }
    """
    result = {
        "forms": [],
        "security_headers": {}
    }
    
    # Track to avoid duplicates
    visited_urls: Set[str] = set()
    forms_found = []
    
    base_domain = urlparse(url).netloc
    
    async def fetch_and_parse(session: aiohttp.ClientSession, target_url: str, depth: int):
        if target_url in visited_urls or depth > max_depth:
            return
            
        visited_urls.add(target_url)
        
        try:
            async with session.get(target_url, timeout=10) as response:
                html = await response.text()
                
                # Capture headers only from the entry point
                if depth == 0:
                    headers = response.headers
                    result["security_headers"] = {
                        "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                        "Content-Security-Policy": headers.get("Content-Security-Policy"),
                        "X-Frame-Options": headers.get("X-Frame-Options")
                    }
                
                soup = BeautifulSoup(html, "html.parser")
                
                # Extract Forms
                for form in soup.find_all("form"):
                    action = urljoin(target_url, form.get("action", ""))
                    inputs = []
                    has_csrf_token = False
                    for input_tag in form.find_all(["input", "textarea"]):
                        name = input_tag.get("name")
                        if name:
                            inputs.append(name)
                            if "csrf" in name.lower() or "token" in name.lower() or "authenticity" in name.lower():
                                has_csrf_token = True
                                
                    form_data = {
                        "action": action,
                        "inputs": inputs,
                        "has_csrf_token": has_csrf_token
                    }
                    if form_data not in forms_found:
                        forms_found.append(form_data)
                
                # Extract Links for deeper spidering
                if depth < max_depth:
                    tasks = []
                    for a_tag in soup.find_all("a"):
                        href = a_tag.get("href")
                        if href:
                            absolute_link = urljoin(target_url, href)
                            # Only crawl internal links
                            if urlparse(absolute_link).netloc == base_domain:
                                tasks.append(fetch_and_parse(session, absolute_link, depth + 1))
                                
                    if tasks:
                        await asyncio.gather(*tasks) # Spawn concurrent crawls!
                        
        except Exception as e:
            print(f"Error crawling {target_url}: {e}")

    # Kick off the async crawling session
    session_headers = {}
    if cookie:
        session_headers["Cookie"] = cookie
        
    async with aiohttp.ClientSession(headers=session_headers) as session:
        await fetch_and_parse(session, url, 0)
        
    result["forms"] = forms_found
    return result

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    print(asyncio.run(crawl(url)))

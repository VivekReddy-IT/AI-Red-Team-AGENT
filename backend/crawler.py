import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Any

def crawl(url: str) -> Dict[str, Any]:
    """
    Crawls a given URL and extracts forms, inputs, and links.
    Returns a dictionary of:
    {
      "forms": [{"action": "/login", "inputs": ["username", "password"]}],
      "links": ["https://example.com/about", ...]
    }
    """
    result = {
        "forms": [],
        "links": [],
        "security_headers": {}
    }
    
    try:
        # 1. Fetch the HTML of the given URL
        # We use a 10s timeout to prevent hanging on slow servers
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Extract headers for analysis
        headers = response.headers
        result["security_headers"] = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options")
        }
        
        # 2. Parse the HTML using BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        
        # 3. Find all <form> tags and extract details
        for form in soup.find_all("form"):
            action = form.get("action", "")
            inputs = []
            has_csrf_token = False
            
            # Find all inputs inside the form
            for input_tag in form.find_all(["input", "textarea"]):
                name = input_tag.get("name")
                if name:  # only care about inputs that have a name attribute
                    inputs.append(name)
                    # Simple heuristic for token
                    if "csrf" in name.lower() or "token" in name.lower() or "authenticity" in name.lower():
                        has_csrf_token = True
                    
            result["forms"].append({
                "action": action,
                "inputs": inputs,
                "has_csrf_token": has_csrf_token
            })
            
        # 4. Find all links (<a href>) on the page
        for a_tag in soup.find_all("a"):
            href = a_tag.get("href")
            if href:
                result["links"].append(href)
                
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")
        # Return empty but safe structures on error
    except Exception as e:
        print(f"Unexpected error crawling {url}: {e}")
        
    return result

if __name__ == "__main__":
    # Simple test run if executed directly
    print(crawl("http://example.com"))

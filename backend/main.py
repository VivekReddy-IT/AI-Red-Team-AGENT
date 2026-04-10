from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from backend.crawler import crawl
from backend.tester import test_sqli, test_xss, test_path_traversal, test_command_injection, test_open_redirect, test_security_headers, test_csrf
from backend.reporter import generate_report
from backend.storage import save_report, load_report

app = FastAPI(title="AI Red Team Agent API")

# Setup CORS to allow the frontend to safely interact
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo purposes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan_url(request: ScanRequest):
    target_url = request.url.strip()
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http:// or https://")
        
    try:
        # Step 1: Crawl
        crawl_results = crawl(target_url)
        forms = crawl_results.get("forms", [])
        
        # Step 2: Test basic vulnerabilities
        sqli_findings = test_sqli(target_url, forms)
        xss_findings = test_xss(target_url, forms)
        lfi_findings = test_path_traversal(target_url, forms)
        cmd_findings = test_command_injection(target_url, forms)
        redirect_findings = test_open_redirect(target_url, forms)
        csrf_findings = test_csrf(target_url, forms)
        
        headers = crawl_results.get("security_headers", {})
        header_findings = test_security_headers(target_url, headers)
        
        all_raw_findings = sqli_findings + xss_findings + lfi_findings + cmd_findings + redirect_findings + header_findings + csrf_findings
        
        # Step 3: AI Reporting layer
        final_findings = generate_report(all_raw_findings)
        
        report_data = {
            "url": target_url,
            "forms_found": len(forms),
            "vulnerabilities": final_findings
        }
        
        # Step 4: Persist Report
        report_id = save_report(report_data)
        
        return {
            "report_id": report_id,
            "url": target_url,
            "forms_found": len(forms),
            "vulnerabilities": final_findings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/report/{report_id}")
async def get_report(report_id: str):
    report_data = load_report(report_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_data

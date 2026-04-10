# AI Red Team Agent

A simple automated web security scanner that finds input forms, attempts SQL Injection and XSS payloads, and generates AI-driven explanations for any vulnerabilities found using Anthropic Claude.

## Architecture

This project was built from scratch following an AI Red Teaming blueprint:

- `backend/crawler.py` - Locates injectable endpoints and checks for CSRF tokens vs Security Headers.
- `backend/tester.py` - Fires payloads for SQLi, XSS, Path Traversal (LFI), Command Injection, and Open Redirects.
- `backend/storage.py` - Persists reports safely and provides secure UUID-based private loading.
- `backend/reporter.py` - Passes triggers to Anthropic Claude 3 for simple, natural language explanations.
- `backend/main.py` - FastAPI orchestration routing.
- `frontend/index.html` - Clean frontend application with "Private UUID" loading support.

## Installation & Setup

1. **Change directory to the project root:**
```bash
cd "/home/viv/AI Project"
```

2. **Setup virtual environment (Optional but Recommended):**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure Settings:**
Edit the `.env` file to include your actual API key.
```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```
*(If you leave the default, the scanner will still run, but you won't get AI explanations for vulnerabilities.)*

## Running the Application

1. **Start the FastAPI backend server:**
```bash
# Needs to run from the security-scanner root folder
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
This starts the backend at `http://127.0.0.1:8000`.

2. **Open the Frontend UI:**
You can just double click `frontend/index.html` or open it in your browser directly:
```bash
# Example assuming file is available locally
google-chrome frontend/index.html
```

3. **Use the Application:**
Paste a test URL (e.g., `http://testphp.vulnweb.com/`) into the input field and click "Scan Target".
Once the scan is done, a **Private Report UUID** will appear above your results. Save it, and you can reload the dashboard with that ID forever without repeating the scan!

## UI & Usage Guide

The AI Red Team Agent provides a clean, Vanillia JS dark-mode frontend that makes navigating vulnerabilities effortless.

### 1. The Dashboard (Empty State)
When you first open the scanner, you are presented with two input options:
- **Scan Target:** Start a fresh vulnerability crawl on a new URL.
- **Load Report:** Instantly reload a previous scan via its Private Report UUID.

![Dashboard Preview] <img width="1534" height="868" alt="Project proof" src="https://github.com/user-attachments/assets/518f4eb4-be22-472a-95a8-95e69f5ca853" />


### 2. Live Scan execution
Paste a vulnerable test URL into the `Target` box (e.g. `http://testphp.vulnweb.com`). As soon as you click *Scan Target*, the system passes the URL to our FastAPI backend. The UI presents a loading spinner while the crawler identifies forms, and the tester blasts safe payloads mapping for SQLi, XSS, Command Injection, and Missing Headers.

![Scanning a Target](/home/viv/.gemini/antigravity/brain/b4efdda3-296d-4bef-a96d-a1cd742b39d3/media__1775845889410.png)

### 3. Understanding the Report
Once complete, the UI instantly populates a dynamic table.
- **Private Report UUID:** A securely generated token (e.g. `341b9a65...`) appears. You can save this to revisit your exact findings later without running another heavy scan.
- **Severity Tagging:** Missing headers or warnings get coded with `Low/Medium` severity logic, while critical injection points receive `High` tags.
- **AI Explanation & Fix:** If you configure the `.env` with a valid Anthropic key, Claude-3 will explicitly describe *how* to patch the code that caused the payload to succeed!

![Reviewing Results](/home/viv/.gemini/antigravity/brain/b4efdda3-296d-4bef-a96d-a1cd742b39d3/media__1775845889438.png)

# AI Red Team Agent (Safe Mode)

A mini automated ethical hacking pipeline:

- **Recon**: `nmap` (service/port scan)
- **Exploit checks**: `sqlmap` (conservative settings)
- **Web scan**: **OWASP ZAP Baseline** (passive + spider) via **Docker fallback**
- **AI report**: Ollama (optional) + strict JSON schema fallback
- **History**: saves every scan as JSON under `results/`

This project enforces **Safe Mode**: only `localhost`/loopback and an allowlist of known test hosts are allowed.

## Requirements

- Ubuntu 24.04+ recommended
- Python 3.12+
- Tools:
  - `nmap`
  - `git`
  - `docker` (for ZAP baseline fallback)
  - sqlmap cloned locally (this project expects `/home/<user>/sqlmap/sqlmap.py`)
- Optional:
  - Ollama (`ollama` + a model like `llama3`)

## Install (system tools)

```bash
sudo apt update
sudo apt install -y nmap git docker.io
sudo systemctl enable --now docker
```

Allow docker without sudo (recommended), then restart your terminal:

```bash
sudo usermod -aG docker $USER
newgrp docker
docker ps >/dev/null && echo docker_without_sudo_ok
```

## Install sqlmap (clone)

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /home/$USER/sqlmap
```

If you cloned it somewhere else, set:

```bash
export SQLMAP_PATH="/absolute/path/to/sqlmap.py"
```

## Optional: Install & run Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama pull llama3
```

## Python dependencies

This project uses:

- FastAPI
- Uvicorn
- Requests
- Pydantic

Install them (recommended in a virtualenv). If you can’t create a venv on Ubuntu, you can use `--break-system-packages` as a last resort.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run the API

From the project folder:

```bash
cd "/home/viv/AI Project"
/home/viv/.local/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Check it:

```bash
curl -s http://127.0.0.1:8000/health
```

## Use the API

Queue a scan:

```bash
curl -s -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"testphp.vulnweb.com/listproducts.php?cat=1"}'
```

Poll a scan:

```bash
curl -s http://127.0.0.1:8000/scan/<scan_id>
```

List recent scans:

```bash
curl -s http://127.0.0.1:8000/scans
```

Open dashboard:

- `http://127.0.0.1:8000/dashboard`

## Outputs

All scan jobs are persisted to:

- `results/<scan_id>.json`

The report (`ai_report`) is always **strict JSON** with keys:

- `title`
- `severity` (`Low|Medium|High`)
- `executive_summary`
- `findings[]`
- `recommended_next_steps[]`

## Safe Mode allowlist

Safe mode validation lives in `app/utils/safety.py`.

If you want to add more approved targets, extend `ALLOWED_HOSTS` there.

## Legal / Ethics

Only scan:

- Your own systems
- Explicitly authorized environments
- Known legal test targets


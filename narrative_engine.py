"""
narrative_engine.py — Project Chimera
Generates a coherent company narrative at session start.
The LLM writes the entire backstory: employees, projects, recent events,
git history, internal messages. Every artifact references this narrative,
making the deception feel inhabited by real people.
"""

from openai import OpenAI
import json
import random
import hashlib

client = OpenAI(
    api_key="YOUR OPEN ROUTER API KEY HERE",
    base_url="https://openrouter.ai/api/v1"
)

COMPANY_ARCHETYPES = [
    {
        "type": "fintech_startup",
        "desc": "Series B fintech startup processing payments",
        "sensitivity": "financial transaction data and PCI-DSS cardholder info",
        "services": ["nginx", "postgresql", "redis", "celery", "stripe-api"],
        "tech_stack": "Python/Django backend, React frontend, PostgreSQL",
    },
    {
        "type": "hospital_network",
        "desc": "regional hospital network managing patient records",
        "sensitivity": "HIPAA-protected patient health information (PHI)",
        "services": ["apache2", "mysql", "hl7-listener", "dicom-server"],
        "tech_stack": "Java EHR system, MySQL, HL7 integration",
    },
    {
        "type": "defense_contractor",
        "desc": "defense contractor working on government contracts",
        "sensitivity": "CUI (Controlled Unclassified Information) and ITAR data",
        "services": ["nginx", "postgresql", "vpn-gateway", "ldap"],
        "tech_stack": "C++/Python, air-gapped systems, classified project repos",
    },
    {
        "type": "ecommerce_platform",
        "desc": "mid-sized e-commerce platform with 2M users",
        "sensitivity": "customer PII, order history, and payment tokens",
        "services": ["nginx", "mysql", "redis", "elasticsearch", "rabbitmq"],
        "tech_stack": "PHP/Laravel, MySQL, ElasticSearch, Redis cache",
    },
    {
        "type": "research_university",
        "desc": "university research computing cluster",
        "sensitivity": "unpublished research data and grant information",
        "services": ["slurm", "nfs-server", "ldap", "jupyter-hub"],
        "tech_stack": "Python/R research cluster, SLURM job scheduler, NFS",
    },
]

FIRST_NAMES = ["james", "sarah", "michael", "priya", "chen", "fatima",
               "david", "maria", "alex", "jessica", "ryan", "aisha"]
LAST_NAMES  = ["mitchell", "patel", "chen", "garcia", "kim", "hassan",
               "johnson", "rodriguez", "lee", "wilson", "taylor", "brown"]
ROLES = {
    "fintech_startup":    ["lead_engineer", "devops", "backend_dev", "security_analyst", "cto"],
    "hospital_network":   ["sys_admin", "hl7_integrator", "network_engineer", "it_director"],
    "defense_contractor": ["senior_engineer", "devops", "security_officer", "program_manager"],
    "ecommerce_platform": ["backend_dev", "devops", "dba", "frontend_dev", "cto"],
    "research_university": ["hpc_admin", "research_engineer", "sys_admin", "grad_student"],
}


def generate_employees(company_type: str, seed: int) -> list:
    rng = random.Random(seed)
    roles = ROLES.get(company_type, ["admin", "devops", "engineer"])
    employees = []
    count = rng.randint(4, 7)
    for i in range(count):
        first = rng.choice(FIRST_NAMES)
        last = rng.choice(LAST_NAMES)
        role = rng.choice(roles)
        employees.append({
            "username": f"{first}.{last}",
            "full_name": f"{first.capitalize()} {last.capitalize()}",
            "role": role,
            "uid": 1000 + i,
            "home": f"/home/{first}.{last}",
        })
    # Always include admin
    employees.append({
        "username": "admin",
        "full_name": "System Administrator",
        "role": "sysadmin",
        "uid": 999,
        "home": "/home/admin",
    })
    return employees


def generate_narrative(session_id: str) -> dict:
    """
    Generate a full company narrative using the LLM.
    Returns a dict with everything needed to populate the fake environment.
    """
    seed = int(hashlib.md5(session_id.encode()).hexdigest()[:8], 16)
    rng = random.Random(seed)

    archetype = rng.choice(COMPANY_ARCHETYPES)
    employees = generate_employees(archetype["type"], seed)
    employee_names = [e["username"] for e in employees]

    prompt = f"""You are generating a realistic fake company profile for a cybersecurity honeypot.
Company type: {archetype['desc']}
Tech stack: {archetype['tech_stack']}
Employees: {', '.join(employee_names)}

Generate a JSON object with these exact fields (no markdown, pure JSON):
{{
  "company_name": "realistic company name",
  "project_codenames": ["3 internal project names"],
  "recent_git_commits": [
    {{"hash": "7char hex", "author": "username from employees", "message": "realistic commit message", "date": "recent date"}},
    {{"hash": "7char hex", "author": "username", "message": "message", "date": "date"}},
    {{"hash": "7char hex", "author": "username", "message": "message", "date": "date"}},
    {{"hash": "7char hex", "author": "username", "message": "message", "date": "date"}}
  ],
  "recent_auth_log_entries": [
    "realistic sshd log line with employee username and internal IP",
    "another log line",
    "another log line",
    "another log line",
    "another log line"
  ],
  "internal_slack_snippet": "3-4 lines of internal chat messages between employees about a recent incident or task, formatted as: [username]: message",
  "cron_jobs": [
    {{"schedule": "cron schedule", "user": "username", "command": "realistic command"}},
    {{"schedule": "cron schedule", "user": "username", "command": "realistic command"}}
  ],
  "known_misconfiguration": "one specific realistic misconfiguration with detail",
  "hostname": "realistic internal hostname like prod-app-01.company-name.internal"
}}

Be specific and realistic. Commit messages should reference the project codenames. Log entries should use employee usernames."""

    try:
        resp = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.choices[0].message.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        narrative = json.loads(raw)
    except Exception as e:
        # Fallback if LLM fails
        narrative = {
            "company_name": "Acme Corp",
            "project_codenames": ["Project Atlas", "Project Nova", "Project Echo"],
            "recent_git_commits": [
                {"hash": "a3f9c12", "author": employee_names[0], "message": "fix: database connection pooling", "date": "2025-04-20"},
                {"hash": "b7d2e45", "author": employee_names[1], "message": "feat: add retry logic to payment processor", "date": "2025-04-19"},
            ],
            "recent_auth_log_entries": [
                f"Apr 20 09:12:03 sshd[2341]: Accepted publickey for {employee_names[0]} from 10.0.0.4 port 54321 ssh2",
                f"Apr 20 11:34:17 sshd[2891]: Accepted password for admin from 10.0.0.15 port 49201 ssh2",
            ],
            "internal_slack_snippet": f"[{employee_names[0]}]: anyone know why prod-db is showing high CPU?\n[admin]: checking now",
            "cron_jobs": [
                {"schedule": "0 2 * * *", "user": "root", "command": "/opt/backup/backup.sh"},
            ],
            "known_misconfiguration": "sudo NOPASSWD enabled for www-data",
            "hostname": f"prod-db-01.internal",
        }

    # Merge archetype data into narrative
    narrative["archetype"] = archetype
    narrative["employees"] = employees
    narrative["employee_usernames"] = employee_names
    narrative["sensitivity"] = archetype["sensitivity"]
    narrative["services"] = archetype["services"]

    return narrative


def build_narrative_files(narrative: dict) -> dict:
    """
    Returns a dict of filepath -> content for narrative-aware file contents.
    These replace/supplement the static FILE_CONTENTS in state_engine.
    """
    employees = narrative["employees"]
    emp_usernames = narrative["employee_usernames"]
    company = narrative.get("company_name", "Acme Corp")

    # /etc/passwd — populated with real employee names
    passwd_lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    ]
    for emp in employees:
        passwd_lines.append(
            f"{emp['username']}:x:{emp['uid']}:{emp['uid']}:{emp['full_name']}:{emp['home']}:/bin/bash"
        )
    passwd = "\n".join(passwd_lines)

    # /var/log/auth.log — real employee activity
    auth_log = "\n".join(narrative.get("recent_auth_log_entries", [
        "Apr 20 09:12:03 prod-db-01 sshd[2341]: Accepted publickey for admin from 10.0.0.4 port 54321 ssh2",
    ]))

    # git log output
    git_commits = narrative.get("recent_git_commits", [])
    git_log_lines = []
    for c in git_commits:
        git_log_lines.append(f"commit {c['hash']}a8f4d2b3e1c9")
        git_log_lines.append(f"Author: {c['author']} <{c['author']}@{company.lower().replace(' ', '')}.com>")
        git_log_lines.append(f"Date:   {c.get('date', 'Mon Apr 20 2025')} 14:23:11 +0000")
        git_log_lines.append(f"\n    {c['message']}\n")
    git_log = "\n".join(git_log_lines)

    # crontab
    cron_jobs = narrative.get("cron_jobs", [])
    cron_lines = ["# Project Chimera crontab", "SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin", ""]
    for job in cron_jobs:
        cron_lines.append(f"{job['schedule']} {job['user']} {job['command']}")
    crontab = "\n".join(cron_lines)

    # internal slack/notes file
    slack_note = f"# Internal #{company.lower().replace(' ', '-')}-ops\n\n{narrative.get('internal_slack_snippet', '')}"

    return {
        "/etc/passwd": passwd,
        "/var/log/auth.log": auth_log,
        "/var/log/git.log": git_log,
        "/etc/crontab": crontab,
        "/home/admin/notes.txt": slack_note,
        "/etc/hostname": narrative.get("hostname", "prod-db-01.internal"),
    }

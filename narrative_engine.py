from __future__ import annotations

from hashlib import sha256

from llm_client import llm_client


def _seed_from_session(session_id: str) -> int:
    return int(sha256(session_id.encode()).hexdigest()[:8], 16)


def generate_narrative(session_id: str) -> dict:
    system = "You generate compact enterprise honeypot narratives as JSON."
    user = (
        f"Create a realistic but synthetic company profile for session {session_id}. "
        "Return JSON with company_name, hostname, services, employees, sensitivity, and known_misconfiguration."
    )
    result = llm_client.complete(system, user, json_mode=True, max_tokens=350)
    if result.parsed:
        out = result.parsed
        out.setdefault("company_name", f"Chimera Labs {session_id[:4]}")
        out.setdefault("hostname", "prod-db-01.internal")
        
        if not isinstance(out.get("services"), list):
            out["services"] = ["nginx", "mysql", "redis"]
        if not isinstance(out.get("employees"), list):
            out["employees"] = [{"username": "admin", "home": "/home/admin"}]
            
        out.setdefault("sensitivity", "internal company data")
        out.setdefault("known_misconfiguration", "sudo NOPASSWD for deploy")
        return out

    return {
        "company_name": f"Chimera Labs {session_id[:4]}",
        "hostname": "prod-db-01.internal",
        "services": ["nginx", "mysql", "redis"],
        "employees": [
            {"username": "admin", "home": "/home/admin"},
            {"username": "deploy", "home": "/home/deploy"},
        ],
        "sensitivity": "internal company data",
        "known_misconfiguration": "sudo NOPASSWD for deploy",
    }


def build_narrative_files(narrative: dict) -> dict[str, str]:
    company = narrative.get("company_name", "Chimera Labs")
    host = narrative.get("hostname", "prod-db-01.internal")
    employees = narrative.get("employees", [])
    if not isinstance(employees, list):
        employees = []
    services = narrative.get("services", [])
    if not isinstance(services, list):
        services = []
    
    passwd_lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    ]
    for i, emp in enumerate(employees):
        uname = emp.get("username", "user")
        home = emp.get("home", f"/home/{uname}")
        uid = 1000 + i
        passwd_lines.append(f"{uname}:x:{uid}:{uid}:{uname.capitalize()}: {home}:/bin/bash")
    
    # Ensure services are strings
    services_str = [str(s) for s in services]
    
    files = {
        "/etc/motd": f"Welcome to {company}\nHost: {host}\nAuthorized access only.\n\nRunning Services: {', '.join(services_str)}",
        "/etc/hostname": host,
        "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {host}\n10.0.0.5 {host.split('.')[0]}",
        "/etc/passwd": "\n".join(passwd_lines),
        "/var/www/html/index.php": f"<?php\n// {company} Internal Portal\necho '<h1>{company} Management Console</h1>';\n?>",
    }
    
    # Add some employee-specific files
    for emp in employees:
        uname = emp.get("username")
        home = emp.get("home")
        if uname and home:
            files[f"{home}/notes.txt"] = f"Property of {company}.\nUser: {uname}\nDo not share credentials."
            
    return files

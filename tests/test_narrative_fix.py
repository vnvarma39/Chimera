import sys
import os
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from llm_engine import _get_narrative, get_terminal_response
from state_engine import get_or_create_session, FILE_CONTENTS

def test_narrative_integration():
    session_id = "test-session-123"
    session = get_or_create_session(session_id)
    
    print(f"Testing narrative generation for session: {session_id}")
    narrative = _get_narrative(session)
    
    print(f"Generated Company: {narrative.get('company_name')}")
    print(f"Generated Hostname: {narrative.get('hostname')}")
    
    # Check if /etc/motd was updated
    motd = FILE_CONTENTS.get("/etc/motd", "")
    print(f"MOTD content:\n{motd}")
    
    if narrative.get('company_name') in motd:
        print("SUCCESS: Company name found in MOTD")
    else:
        print("FAILURE: Company name NOT found in MOTD")
        
    # Check if employees were added to filesystem
    for emp in narrative.get("employees", []):
        home = emp.get("home")
        if home in session.filesystem:
            print(f"SUCCESS: Employee home {home} found in filesystem")
        else:
            print(f"FAILURE: Employee home {home} NOT found in filesystem")

    # Test terminal response for hostname
    hostname_resp = get_terminal_response("hostname", session)
    print(f"Terminal 'hostname' response: {hostname_resp}")
    if hostname_resp == narrative.get("hostname"):
        print("SUCCESS: Terminal hostname matches narrative")
    else:
        print("FAILURE: Terminal hostname mismatch")

if __name__ == "__main__":
    # Mock LLM client if needed or ensure API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not set, using fallback narrative")
    
    test_narrative_integration()

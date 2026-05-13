from state_engine import SessionState


def test_session_logging():
    s = SessionState("abc12345")
    tags = s.log_command("whoami")
    assert any(t["id"] == "T1033" for t in tags)


def test_d_score_stored():
    s = SessionState("abc12345")
    s.log_command("whoami", osi_layer="Application", d_score=0.72)
    assert s.d_scores == [0.72]
    assert s.command_log[0]["d_score"] == 0.72
    assert s.command_log[0]["osi_layer"] == "Application"


def test_mitre_privilege():
    s = SessionState("abc12345")
    tags = s.log_command("sudo su")
    ids = {t["id"] for t in tags}
    assert "T1548" in ids

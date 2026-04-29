import socket
import threading
import paramiko
import uuid
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))
from state_engine import get_or_create_session, save_session
from llm_engine import get_terminal_response, get_transcript, get_narrative_for_session
from red_team import run_red_team_analysis, save_redteam_findings

RED_TEAM_EVERY = 10  # run red team analysis every N commands

HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "host_key")
LISTEN_PORT = 2222
BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"


class ChimeraSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Accept everything — it's a honeypot
        print(f"  [AUTH] username={username} password={password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True


def handle_connection(client_socket, client_addr):
    session_id = str(uuid.uuid4())[:8]
    print(f"\n[+] New connection from {client_addr[0]}:{client_addr[1]} — session {session_id}")

    session = get_or_create_session(session_id)

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1"

        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        transport.add_server_key(host_key)

        server = ChimeraSSHServer()
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            print(f"  [!] No channel opened for {session_id}")
            return

        server.event.wait(10)

        # Send welcome banner
        welcome = (
            f"\r\nWelcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n"
            f"\r\n * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f"\r\n  System information as of {time.strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n\r\n"
            f"Last login: Fri Mar 28 08:47:12 2025 from 10.0.0.15\r\n"
        )
        channel.send(welcome.encode())

        def prompt():
            user = session.user
            host = "prod-db-01"
            cwd = session.cwd.replace("/home/admin", "~")
            symbol = "#" if session.user == "root" else "$"
            return f"{user}@{host}:{cwd}{symbol} ".encode()

        channel.send(prompt())

        buffer = ""
        while True:
            if not channel.active:
                break

            try:
                data = channel.recv(1024)
            except Exception:
                break

            if not data:
                break

            for byte in data:
                char = chr(byte)

                if char in ("\r", "\n"):
                    channel.send(b"\r\n")
                    command = buffer.strip()
                    buffer = ""

                    if not command:
                        channel.send(prompt())
                        continue

                    print(f"  [{session_id}] $ {command}")

                    # Log and tag
                    tags = session.log_command(command)
                    if tags:
                        tag_str = ", ".join(f"{t['id']}:{t['name']}" for t in tags)
                        print(f"  [{session_id}] MITRE → {tag_str}")

                    # Update state for mutating commands
                    session.update_fs(command)

                    # Handle exit
                    if command.lower() in ("exit", "logout"):
                        channel.send(b"logout\r\n")
                        save_session(session)
                        channel.close()
                        return

                    # Red team analysis — background thread every N commands
                    cmd_count = len(session.command_log)
                    if cmd_count > 0 and cmd_count % RED_TEAM_EVERY == 0:
                        def _run_rt(sid=session_id, s=session):
                            try:
                                narrative = get_narrative_for_session(sid)
                                transcript = get_transcript(sid)
                                findings = run_red_team_analysis(transcript, narrative)
                                save_redteam_findings(sid, findings)
                                print(f"  [RED TEAM] {sid}: risk={findings.get('detection_risk')} fooled={findings.get('would_i_be_fooled')}")
                            except Exception as e:
                                print(f"  [RED TEAM] Error: {e}")
                        threading.Thread(target=_run_rt, daemon=True).start()

                    # Get LLM response
                    response = get_terminal_response(command, session)

                    if response:
                        # Normalize line endings for terminal
                        response = response.replace("\n", "\r\n")
                        channel.send((response + "\r\n").encode(errors="replace"))

                    channel.send(prompt())

                elif byte == 127 or byte == 8:  # Backspace
                    if buffer:
                        buffer = buffer[:-1]
                        channel.send(b"\b \b")

                elif byte == 3:  # Ctrl+C
                    channel.send(b"^C\r\n")
                    buffer = ""
                    channel.send(prompt())

                elif char.isprintable():
                    buffer += char
                    channel.send(char.encode())

    except Exception as e:
        print(f"  [!] Session {session_id} error: {e}")
    finally:
        save_session(session)
        print(f"[-] Session {session_id} closed")
        try:
            client_socket.close()
        except Exception:
            pass


def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.listen(5)

    print(f"""
╔══════════════════════════════════════════════════╗
║         PROJECT CHIMERA — SSH Honeypot           ║
║                                                  ║
║  Listening on port {LISTEN_PORT}                       ║
║  Connect: ssh admin@localhost -p {LISTEN_PORT}          ║
║  Password: anything                              ║
║                                                  ║
║  Dashboard: streamlit run dashboard.py           ║
╚══════════════════════════════════════════════════╝
""")

    try:
        while True:
            client, addr = sock.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client, addr),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Chimera...")
        sock.close()


if __name__ == "__main__":
    run_server()

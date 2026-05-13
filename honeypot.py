from __future__ import annotations

"""
honeypot.py — Project Chimera (fixed)

FIX 2: every real SSH command now goes through controller.receive_command()
which handles OSI classification, GAN online update, and memory logging
before the terminal response is generated.

FIX 3: red-team runs are delegated to controller.run_red_team() so that
patches get stored in the controller and picked up by llm_engine on the
very next command.
"""

import socket
import threading
import time
import uuid
from pathlib import Path

import paramiko

from agents.controller import MultiAgentController
from config import LISTEN_HOST, LISTEN_PORT
from llm_engine import (
    get_narrative_for_session,
    get_terminal_response,
    get_transcript,
    register_controller,
)
from state_engine import get_or_create_session, save_session

HOST_KEY_PATH = Path(__file__).parent / "host_key"
RED_TEAM_EVERY = 10


class ChimeraSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print(f"  [AUTH] username={username} password={password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_connection(client_socket, client_addr):
    session_id = str(uuid.uuid4())[:8]
    session = get_or_create_session(session_id)
    print(f"\n[+] {client_addr[0]}:{client_addr[1]} → session {session_id}")

    # FIX 2: create controller and register it so llm_engine can pull patches
    controller = MultiAgentController(session_id)
    register_controller(session_id, controller)
    controller.start()

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1"
        host_key = paramiko.RSAKey(filename=str(HOST_KEY_PATH))
        transport.add_server_key(host_key)
        server = ChimeraSSHServer()
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return
        server.event.wait(10)

        # Ensure narrative is generated early
        narrative = get_narrative_for_session(session_id)
        if not narrative:
            # Trigger generation if not already done
            from llm_engine import _get_narrative
            narrative = _get_narrative(session)

        company = narrative.get("company_name", "Chimera Labs")
        hostname = narrative.get("hostname", "prod-db-01.internal")
        host_short = hostname.split(".")[0]

        banner = (
            f"\r\nWelcome to {company} - {hostname}\r\n"
            "Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n"
            f"Last login: {time.strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
        )
        channel.send(banner.encode())

        def prompt():
            symbol = "#" if session.user == "root" else "$"
            # Refresh narrative in case it changed
            curr_narrative = get_narrative_for_session(session_id)
            h = curr_narrative.get("hostname", host_short).split(".")[0]
            return f"{session.user}@{h}:{session.cwd}{symbol} ".encode()

        channel.send(prompt())
        buf = ""

        while channel.active:
            data = channel.recv(1024)
            if not data:
                break

            for byte in data:
                char = chr(byte)

                if char in ("\r", "\n"):
                    channel.send(b"\r\n")
                    command = buf.strip()
                    buf = ""
                    if not command:
                        channel.send(prompt())
                        continue

                    print(f"  [{session_id}] $ {command}")

                    # FIX 2: route real command through controller first
                    meta = controller.receive_command(command)
                    print(f"  [{session_id}] OSI={meta['osi_layer']} D-score={meta['d_score']:.3f}")

                    tags = session.log_command(command, osi_layer=meta["osi_layer"], d_score=meta["d_score"])
                    if tags:
                        print(f"  [{session_id}] MITRE → {', '.join(t['id'] for t in tags)}")

                    session.update_fs(command)

                    if command.lower() in ("exit", "logout"):
                        channel.send(b"logout\r\n")
                        save_session(session)
                        controller.stop()
                        channel.close()
                        return

                    # FIX 3: red-team runs go through controller so patches are stored
                    cmd_count = len(session.command_log)
                    if cmd_count > 0 and cmd_count % RED_TEAM_EVERY == 0:
                        def _rt(sid=session_id, ctrl=controller):
                            try:
                                narrative = get_narrative_for_session(sid)
                                transcript = get_transcript(sid)
                                ctrl.run_red_team(transcript, narrative)
                                patches = ctrl.get_gan_patches()
                                print(f"  [GAN] {len(patches)} total patches active for {sid}")
                            except Exception as e:
                                print(f"  [RED TEAM] Error: {e}")
                        threading.Thread(target=_rt, daemon=True).start()

                    response = get_terminal_response(command, session)
                    if response:
                        channel.send((response.replace("\n", "\r\n") + "\r\n").encode(errors="replace"))
                    channel.send(prompt())

                elif byte in (8, 127):
                    if buf:
                        buf = buf[:-1]
                        channel.send(b"\b \b")
                elif byte == 3:
                    channel.send(b"^C\r\n")
                    buf = ""
                    channel.send(prompt())
                elif char.isprintable():
                    buf += char
                    channel.send(char.encode())

    except Exception as e:
        print(f"  [!] Session {session_id} error: {e}")
    finally:
        save_session(session)
        controller.stop()
        try:
            client_socket.close()
        except Exception:
            pass
        print(f"[-] Session {session_id} closed")


def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(5)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║         PROJECT CHIMERA — SSH Honeypot (fixed)           ║
║                                                          ║
║  FIX 1: GAN trains on real command feature vectors       ║
║  FIX 2: Agents wired to live SSH session                 ║
║  FIX 3: Red-team patches injected into generator prompt  ║
║                                                          ║
║  Listening on {LISTEN_HOST}:{LISTEN_PORT}                        ║
║  ssh admin@localhost -p {LISTEN_PORT}  (any password)           ║
║  Dashboard: streamlit run dashboard.py                   ║
╚══════════════════════════════════════════════════════════╝
""")

    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Chimera...")
    finally:
        sock.close()


if __name__ == "__main__":
    run_server()

"""
serve_dashboard.py — Project Chimera
Tiny HTTP server that serves the React dashboard (bundle.html) and
exposes the data/ JSON files so the frontend can fetch them.

Usage:  python serve_dashboard.py
Opens:  http://localhost:8080
"""
import http.server
import json
import os
import socketserver
import webbrowser
from pathlib import Path

PORT = 8080
ROOT = Path(__file__).parent


class ChimeraHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve data files directly
        if self.path.startswith("/data/"):
            fname = self.path.split("?")[0]   # strip ?t=cache-bust
            fpath = ROOT / fname.lstrip("/")
            if fpath.exists():
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(fpath.read_bytes())
            else:
                # Return empty JSON so the frontend doesn't crash
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"{}")
            return

        # Everything else: serve bundle.html
        bundle = ROOT / "dashboard_bundle.html"
        if bundle.exists():
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(bundle.read_bytes())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"dashboard_bundle.html not found")

    def log_message(self, fmt, *args):
        pass   # silence request logs


if __name__ == "__main__":
    # Make sure data dir exists
    (ROOT / "data").mkdir(exist_ok=True)

    print(f"""
╔══════════════════════════════════════════╗
║   Project Chimera — React Dashboard      ║
║   http://localhost:{PORT}                    ║
╚══════════════════════════════════════════╝
""")
    webbrowser.open(f"http://localhost:{PORT}")
    with socketserver.TCPServer(("", PORT), ChimeraHandler) as httpd:
        httpd.serve_forever()

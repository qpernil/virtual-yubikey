#!/usr/bin/env python3
"""Serve the manual WebAuthn qualification fixture on loopback only."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ASSETS = Path(__file__).resolve().parent / "fido-browser-test"
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/test.js": ("test.js", "text/javascript; charset=utf-8"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(urlsplit(self.path).path)
        if route is None:
            self.send_error(404)
            return
        name, content_type = route
        content = (ASSETS / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8769)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"Open http://localhost:{args.port}/ in the browser connected to the gadget.", flush=True)
        print("Press Ctrl-C to stop. Device configuration is unchanged by this server.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

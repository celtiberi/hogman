#!/usr/bin/env python3
"""Minimal localhost-only HTTP server serving a rotatable canary secret.

Binds strictly to 127.0.0.1 so it is unreachable over the Docker bridge and
can only be reached through Hogman's pen mesh via `hogman-join share`.
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_handler(secret_path: Path, pen_name: str):
    class CanaryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                secret = secret_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"canary unreadable: {exc}\n".encode("utf-8"))
                return

            body = f"pen={pen_name}\ncanary={secret}\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            return

    return CanaryHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a rotatable canary secret on 127.0.0.1.")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--pen", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), make_handler(args.secret_file, args.pen))
    server.serve_forever()


if __name__ == "__main__":
    main()

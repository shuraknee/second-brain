#!/usr/bin/env python3
"""HTTP over one filesystem Unix socket, with one fixed loopback upstream."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import socketserver
from urllib.parse import urlsplit

CSP = "; ".join(["default-src 'self'", "connect-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob:",
    "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
    "font-src 'self' data:", "worker-src 'self' blob:", "frame-src 'self' blob:",
    "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'"])
HOP = {'connection', 'transfer-encoding', 'keep-alive', 'proxy-authenticate',
       'proxy-authorization', 'te', 'trailer', 'upgrade', 'content-length'}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def forward(self):
        if not self.path.startswith('/') or self.path.startswith('//') or self.headers.get('Transfer-Encoding'):
            self.send_error(400)
            return
        if self.headers.get('Host') != self.server.authority:
            self.send_error(421)
            return
        upstream = None
        try:
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 16 * 1024 * 1024:
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in HOP and not key.lower().startswith('x-forwarded-')}
            headers['X-Forwarded-Host'] = self.server.authority
            headers['X-Forwarded-Proto'] = self.server.scheme
            upstream = http.client.HTTPConnection('127.0.0.1', self.server.backend_port, timeout=120)
            upstream.request(self.command, self.path, body, headers)
            response = upstream.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP and key.lower() != 'content-security-policy':
                    self.send_header(key, value)
            self.send_header('Content-Security-Policy', CSP)
            self.send_header('Referrer-Policy', 'same-origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
            has_body = self.command != 'HEAD' and response.status >= 200 and response.status not in [204, 304]
            if has_body:
                self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            if has_body:
                while True:
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    self.wfile.write(('%x\r\n' % len(chunk)).encode() + chunk + b'\r\n')
                    self.wfile.flush()
                self.wfile.write(b'0\r\n\r\n')
        except (OSError, http.client.HTTPException):
            self.close_connection = True
        finally:
            if upstream:
                upstream.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = forward


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if config.get('status') != 'target-approved':
        raise RuntimeError('Target not approved')
    public = urlsplit(config['public_url'])
    socket_path = Path(config['gateway_socket'])
    if socket_path.exists() or socket_path.is_symlink():
        raise RuntimeError('Existing gateway socket/path; inspect owner before cleanup')
    with Server(str(socket_path), Handler) as server:
        socket_path.chmod(0o600)
        server.authority = public.netloc
        server.scheme = public.scheme
        server.backend_port = config['backend_port']
        server.serve_forever()


if __name__ == '__main__':
    main()

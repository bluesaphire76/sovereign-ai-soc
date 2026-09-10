"""Read-only route/assets smoke after the authorized frontend-only restart.

The local Next cookie handlers are also exercised with a dummy token, never real
credentials. No backend mutation, service restart or external request is performed.
"""
import hashlib
import http.client
import json
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
ROUTES = ("/login", "/admin/users", "/system-information/security-audit",
          "/security-audit", "/admin/security-audit")
ALIASES = ROUTES[-2:]


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        value = attrs.get("src") if tag == "script" else attrs.get("href") if tag == "link" else None
        if value and value.startswith("/_next/static/"):
            self.paths.add(value)


def request(port, path, method="GET", payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": "soc.varqon.net", "Accept-Encoding": "identity"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def main():
    # systemd can report active briefly before next-server binds its socket.
    for attempt in range(30):
        try:
            request(3000, "/login", "HEAD")
            break
        except ConnectionRefusedError:
            if attempt == 29:
                raise
            time.sleep(0.5)
    build_id = (ROOT / "frontend/.next/BUILD_ID").read_text().strip()
    all_assets = set()
    for port in (3000, 8088):
        for route in ROUTES:
            status, headers, body = request(port, route)
            assert status == (307 if route in ALIASES else 200), (port, route, status)
            head_status, _, _ = request(port, route, "HEAD")
            assert head_status == status
            if route in ALIASES:
                assert urlsplit(headers["location"]).path == ROUTES[2]
            else:
                parser = Assets()
                parser.feed(body.decode())
                assert any(urlsplit(p).path.endswith(".js") for p in parser.paths)
                assert any(urlsplit(p).path.endswith(".css") for p in parser.paths)
                all_assets.update(parser.paths)
            print(f"{port} GET/HEAD {route}: {status} PASS", flush=True)
    for asset in sorted(all_assets):
        disk_path = ROOT / "frontend/.next" / unquote(urlsplit(asset).path.removeprefix("/_next/"))
        expected = hashlib.sha256(disk_path.read_bytes()).hexdigest()
        for port in (3000, 8088):
            status, _, data = request(port, asset)
            assert status == 200, (port, asset, status)
            assert hashlib.sha256(data).hexdigest() == expected, (port, asset, "disk/runtime mismatch")
        print(f"3000 + 8088 asset {asset}: 200, SHA-256 equals disk PASS", flush=True)
    for port in (3000, 8088):
        status, _, _ = request(port, "/api/auth/session", "POST", {})
        assert status == 400
        status, headers, _ = request(port, "/api/auth/session", "POST",
                                     {"token": "ux11-cookie-fixture", "max_age_seconds": 999999})
        assert status == 200
        cookie = SimpleCookie(headers["set-cookie"])["ai_soc_access_token"]
        assert cookie["httponly"] and cookie["secure"]
        assert cookie["samesite"].lower() == "lax" and cookie["path"] == "/"
        assert cookie["max-age"] == "28800"
        status, headers, _ = request(port, "/api/auth/logout", "POST")
        assert status == 200
        assert SimpleCookie(headers["set-cookie"])["ai_soc_access_token"]["max-age"] == "0"
        print(f"{port} local session/logout cookie flags, max age and cleanup: PASS", flush=True)
    print(f"Build {build_id}: {len(all_assets)} current assets match disk on BOTH paths. PASS")


if __name__ == "__main__":
    main()

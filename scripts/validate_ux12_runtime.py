"""Current production HTML/assets on Next and Nginx; no backend mutations.

Run only after the authorized frontend-only restart, with safe existing entity IDs.
The UX-11 validator additionally retains the real local cookie-handler contracts.
"""
import argparse
import hashlib
import json
import time
from urllib.parse import unquote, urlsplit

from validate_ux11_runtime import Assets, ROOT, request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident-id", required=True, type=int)
    parser.add_argument("--case-id", required=True, type=int)
    args = parser.parse_args()
    assert args.incident_id > 0 and args.case_id > 0
    aliases = {
        "/security-audit": "/system-information/security-audit",
        "/admin/security-audit": "/system-information/security-audit",
        "/operation-history": "/system-information/operation-history",
        "/admin/operation-history": "/system-information/operation-history",
    }
    manifest = json.loads((ROOT / "frontend/.next/server/app-paths-manifest.json").read_text())
    pages = [key.removesuffix("/page") or "/" for key in manifest if key.endswith("/page")]
    pages = [p for p in pages if not p.startswith("/_")]
    routes = [p.replace("[id]", str(args.incident_id if p.startswith("/incidents/") else args.case_id)) for p in pages]
    assert len(routes) == 24, routes
    for attempt in range(30):
        try:
            request(3000, "/login", "HEAD")
            break
        except ConnectionRefusedError:
            if attempt == 29:
                raise
            time.sleep(0.5)
    assets = set()
    for port in (3000, 8088):
        for route in sorted(routes):
            status, headers, body = request(port, route)
            expected = 307 if route in aliases else 200
            assert status == expected, (port, route, status)
            assert request(port, route, "HEAD")[0] == expected
            if route in aliases:
                assert urlsplit(headers["location"]).path == aliases[route]
            else:
                parsed = Assets()
                parsed.feed(body.decode())
                assert any(urlsplit(p).path.endswith(".js") for p in parsed.paths)
                assert any(urlsplit(p).path.endswith(".css") for p in parsed.paths)
                assets.update(parsed.paths)
            print(f"{port} GET/HEAD {route}: {expected} PASS", flush=True)
        assert request(port, "/ux12-nonexistent-route")[0] == 404
        assert request(port, "/favicon.ico")[0] == 200
    assert any(urlsplit(p).path.endswith(".woff2") for p in assets), "Current font preload missing"
    for asset in sorted(assets):
        disk = ROOT / "frontend/.next" / unquote(urlsplit(asset).path.removeprefix("/_next/"))
        expected = hashlib.sha256(disk.read_bytes()).hexdigest()
        for port in (3000, 8088):
            status, _, data = request(port, asset)
            assert status == 200, (port, asset, status)
            assert hashlib.sha256(data).hexdigest() == expected, (port, asset, "hash mismatch")
        print(f"3000 + 8088 {asset}: 200 SHA-256 == disk PASS", flush=True)
    build_id = (ROOT / "frontend/.next/BUILD_ID").read_text().strip()
    print(json.dumps({"build_id": build_id, "manifest_entries": len(manifest), "pages_and_aliases": len(routes),
                      "assets": len(assets), "origins": [3000, 8088], "host": "soc.varqon.net", "result": "PASS"}))


if __name__ == "__main__":
    main()

"""Emit build-local artifact identities; never reads runtime credentials."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import urllib.request
from pathlib import Path


def manifest(root: Path) -> dict:
    paths = [
        "opt/opensandbox-egress/egress",
        "opt/opensandbox-egress/supervisor",
        "opt/opensandbox-egress/cleanup.sh",
        "opt/opensandbox-egress/public_egress_manifest.py",
        "var/lib/mitmproxy/.mitmproxy/config.yaml",
    ]
    paths.extend(
        str(path.relative_to(root)).replace("\\", "/")
        for path in sorted((root / "var/egress/mitmscripts").glob("*.py"))
    )
    required = {"system.py", "public_policy.py", "upstream_proxy.py"}
    if not required.issubset({Path(path).name for path in paths}):
        raise ValueError("public-egress bundled addon is missing")
    return {
        "schema_version": 1,
        "profile": "bprime-root-v1",
        "python": platform.python_version(),
        "mitmproxy": importlib.metadata.version("mitmproxy"),
        "sha256": {
            "/" + path: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for path in sorted(paths)
        },
    }


def check_ready(root: Path) -> None:
    """Gate native-sidecar startup on the shipped profile and live MITM gate.

    An older image's generic /healthz is insufficient: it may ignore every
    strict-policy environment variable. Missing/changed artifacts fail closed.
    This checks build consistency, not authenticity; pin the registry digest.
    """
    expected = json.loads(
        (root / "opt/opensandbox-egress/public-egress-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    actual = manifest(root)
    if expected != actual or actual["mitmproxy"] != "11.0.2":
        raise ValueError("public-egress image identity mismatch")

    # Do not consult HTTP(S)_PROXY or redirects for a local readiness probe.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open("http://127.0.0.1:18080/healthz", timeout=2) as response:
        if response.status != 200 or response.read(16) != b"ok":
            raise ValueError("public-egress stack not ready")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--check-ready", action="store_true")
    args = parser.parse_args()
    if args.check_ready:
        try:
            check_ready(args.root)
        except Exception:
            # Probe output is visible in Pod events. Never dump file contents.
            print("public-egress image or stack not ready", file=sys.stderr)
            sys.exit(1)
    else:
        args.output.write_text(
            json.dumps(manifest(args.root), indent=2) + "\n", encoding="utf-8"
        )

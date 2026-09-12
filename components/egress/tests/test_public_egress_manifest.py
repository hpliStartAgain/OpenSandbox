"""Build-manifest checks use only disposable synthetic image files."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class PublicEgressManifestTest(unittest.TestCase):
    def test_manifest_records_installed_bytes_and_requires_all_addons(self):
        source = Path(__file__).parents[1] / "scripts/public_egress_manifest.py"
        spec = importlib.util.spec_from_file_location("public_manifest_fixture", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                "opt/opensandbox-egress/egress",
                "opt/opensandbox-egress/supervisor",
                "opt/opensandbox-egress/cleanup.sh",
                "opt/opensandbox-egress/public_egress_manifest.py",
                "var/lib/mitmproxy/.mitmproxy/config.yaml",
                "var/egress/mitmscripts/system.py",
                "var/egress/mitmscripts/public_policy.py",
                "var/egress/mitmscripts/upstream_proxy.py",
            ]
            for path in paths:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.encode())
            with patch.object(
                module.importlib.metadata, "version", return_value="11.0.2"
            ):
                value = module.manifest(root)
                self.assertEqual(value["mitmproxy"], "11.0.2")
                self.assertEqual(len(value["sha256"]), len(paths))
                for path in paths:
                    self.assertEqual(
                        value["sha256"]["/" + path],
                        hashlib.sha256(path.encode()).hexdigest(),
                    )
                saved = root / "opt/opensandbox-egress/public-egress-manifest.json"
                saved.write_text(json.dumps(value), encoding="utf-8")
                response = MagicMock()
                response.status = 200
                response.read.return_value = b"ok"
                opener = MagicMock()
                opener.open.return_value.__enter__.return_value = response
                with patch.object(
                    module.urllib.request, "build_opener", return_value=opener
                ):
                    module.check_ready(root)
                    opener.open.assert_called_once_with(
                        "http://127.0.0.1:18080/healthz", timeout=2
                    )
                    response.status = 503
                    with self.assertRaisesRegex(ValueError, "stack not ready"):
                        module.check_ready(root)
                    response.status = 200
                    response.read.return_value = b"not the health endpoint"
                    with self.assertRaisesRegex(ValueError, "stack not ready"):
                        module.check_ready(root)
                    (root / paths[0]).write_bytes(b"changed binary")
                    with self.assertRaisesRegex(ValueError, "identity mismatch"):
                        module.check_ready(root)
                    saved.unlink()
                    with self.assertRaises(FileNotFoundError):
                        module.check_ready(root)
                (root / paths[-1]).unlink()
                with self.assertRaisesRegex(ValueError, "addon is missing"):
                    module.manifest(root)


if __name__ == "__main__":
    unittest.main()

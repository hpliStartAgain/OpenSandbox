# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bounded, generation-fenced TLS connection admission foundation."""

import hashlib
import importlib.util
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MITMSCRIPTS = Path(__file__).resolve().parents[1] / "mitmscripts"


def load(name):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, MITMSCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


receiver = load("revision_receiver")
selectors = load("host_selectors")
load("decision_snapshot")
decision = load("tls_decision")
registry_module = load("tls_registry")


class TLSRegistryTest(unittest.TestCase):
    identity = ("control-a", "subject-a")

    def snapshot(self, epoch=1, host="api.example.com", identity=None):
        control, subject = identity or self.identity
        bindings = [] if host is None else [{
            "name": "binding-a",
            "match": {
                "schemes": ["https"],
                "hosts": [host],
                "methods": ["GET"],
                "paths": ["/api/*"],
            },
            "headers": [],
        }]
        payload = {
            "version": 1,
            "vaultRevision": 1 if bindings else 0,
            "effectivePolicyEpoch": 1,
            "interceptionMode": "credential-bound",
            "state": "active" if bindings else "active-empty",
            "tlsBindingHostSelectors": [] if host is None else [host],
            "fullRenderedBindings": bindings,
            "redactions": [],
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        revision = receiver.Revision(
            control, subject, epoch, payload["vaultRevision"], 1,
            hashlib.sha256(raw).hexdigest(),
        )
        return receiver.Snapshot(revision, raw)

    def admit(self, registry, sni="api.example.com", identity=None, **kwargs):
        return registry.admit(
            identity=self.identity if identity is None else identity,
            sni=sni,
            ech_hidden=kwargs.pop("ech_hidden", False),
            static_passthrough=kwargs.pop("static_passthrough", ()),
        )

    def test_unknown_snapshot_denies_but_early_passthrough_stays_available(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        denied = self.admit(registry)
        self.assertEqual((denied.action, denied.reason, denied.token),
                         ("deny", "snapshot_missing", None))
        self.assertEqual(self.admit(registry, ech_hidden=True).reason, "ech")
        self.assertEqual(self.admit(registry, sni=None).reason, "no_sni")
        self.assertEqual(registry.count, 0)

    def test_bound_capacity_never_downgrades_and_release_is_idempotent(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(self.snapshot())
        first = self.admit(registry)
        self.assertEqual((first.action, first.reason), ("decrypt", "binding_host"))
        self.assertIsNotNone(first.token)
        full = self.admit(registry)
        self.assertEqual((full.action, full.reason, full.token),
                         ("deny", "registry_exhausted", None))
        self.assertEqual(self.admit(registry, sni="other.example.com").action,
                         "passthrough")
        self.assertEqual(registry.count, 1)
        self.assertTrue(registry.release(first.token))
        self.assertFalse(registry.release(first.token))
        self.assertEqual(self.admit(registry).action, "decrypt")

    def test_epoch_change_affects_new_admissions_but_keeps_old_entry_tracked(self):
        registry = registry_module.BoundConnectionRegistry(capacity=2)
        registry.activate(self.snapshot())
        old = self.admit(registry)
        registry.activate(self.snapshot(epoch=2, host="new.example.com"))
        self.assertEqual(self.admit(registry).action, "passthrough")
        new = self.admit(registry, sni="new.example.com")
        self.assertEqual((new.action, new.token.revision.decision_epoch),
                         ("decrypt", 2))
        self.assertEqual(registry.count, 2)
        self.assertTrue(registry.release(old.token))
        self.assertEqual(registry.count, 1)

    def test_stale_epoch_and_generation_replacement_with_live_entries_fail_closed(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(self.snapshot(epoch=2))
        old = self.admit(registry)
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(epoch=1))
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(identity=("control-b", "subject-b")))
        self.assertEqual(self.admit(registry, identity=("control-b", "subject-b")).reason,
                         "generation_mismatch")
        self.assertEqual(registry.count, 1)
        self.assertTrue(registry.release(old.token))
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(identity=("control-b", "subject-b")))
        self.assertEqual(registry.count, 0)

    def test_invalid_capacity_and_malformed_static_input_fail_closed(self):
        for capacity in (0, -1, True, "1"):
            with self.subTest(capacity=capacity):
                with self.assertRaises(ValueError):
                    registry_module.BoundConnectionRegistry(capacity=capacity)
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(self.snapshot())
        result = self.admit(registry, static_passthrough=("api.example.com",))
        self.assertEqual((result.action, result.reason, result.token),
                         ("deny", "invalid_input", None))
        self.assertEqual(registry.count, 0)

    def test_deactivate_denies_new_tls_and_retains_old_entries_for_closure(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(self.snapshot())
        old = self.admit(registry)
        self.assertEqual(registry.deactivate(), (old.token,))
        self.assertEqual(self.admit(registry).reason, "snapshot_missing")
        self.assertEqual(registry.count, 1)
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(identity=("control-b", "subject-b")))
        self.assertTrue(registry.release(old.token))
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(identity=("control-b", "subject-b")))

    def test_token_from_another_registry_cannot_release_same_serial(self):
        first_registry = registry_module.BoundConnectionRegistry(capacity=1)
        second_registry = registry_module.BoundConnectionRegistry(capacity=1)
        view = self.snapshot()
        first_registry.activate(view)
        second_registry.activate(view)
        first = self.admit(first_registry)
        second = self.admit(second_registry)
        self.assertFalse(second_registry.release(first.token))
        self.assertEqual(second_registry.count, 1)
        self.assertTrue(second_registry.release(second.token))

    def test_generation_is_immutable_even_without_entries(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(self.snapshot(epoch=9))
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(identity=("control-b", "subject-b")))

    def test_activation_rejects_unvalidated_selector_view(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        forged = decision.TLSSelectorView(
            receiver.Revision("control-a", "subject-a", 1, 1, 1, "0" * 64),
            (),
        )
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(forged)

    def test_wildcard_to_exact_returns_only_newly_uncovered_memberships(self):
        registry = registry_module.BoundConnectionRegistry(capacity=3)
        registry.activate(self.snapshot(host="*.example.com"))
        api = self.admit(registry, sni="API.EXAMPLE.COM.")
        docs = self.admit(registry, sni="docs.example.com")
        nested = self.admit(registry, sni="a.b.example.com")

        uncovered = registry.activate(self.snapshot(epoch=2, host="api.example.com"))

        self.assertEqual(uncovered, (docs.token, nested.token))
        self.assertEqual(registry.count, 3)
        self.assertEqual(self.admit(registry, sni="docs.example.com").action,
                         "passthrough")
        self.assertTrue(registry.release(api.token))
        self.assertTrue(registry.release(docs.token))
        self.assertTrue(registry.release(nested.token))

    def test_exact_to_wildcard_keeps_existing_host_covered(self):
        registry = registry_module.BoundConnectionRegistry(capacity=2)
        registry.activate(self.snapshot())
        api = self.admit(registry)

        self.assertEqual(registry.activate(
            self.snapshot(epoch=2, host="*.example.com")), ())
        docs = self.admit(registry, sni="docs.example.com")
        self.assertEqual((docs.action, registry.count), ("decrypt", 2))
        self.assertTrue(registry.release(api.token))

    def test_empty_and_unchanged_host_transitions_do_not_repeat_old_uncoverage(self):
        registry = registry_module.BoundConnectionRegistry(capacity=2)
        registry.activate(self.snapshot(host="*.example.com"))
        api = self.admit(registry)
        docs = self.admit(registry, sni="docs.example.com")

        self.assertEqual(registry.activate(
            self.snapshot(epoch=2, host="api.example.com")), (docs.token,))
        self.assertEqual(registry.activate(
            self.snapshot(epoch=3, host="api.example.com")), ())
        self.assertEqual(registry.activate(
            self.snapshot(epoch=4, host=None)), (api.token,))
        self.assertEqual(registry.count, 2)
        self.assertEqual(self.admit(registry).action, "passthrough")

    def test_rejected_transition_preserves_old_view_and_memberships(self):
        registry = registry_module.BoundConnectionRegistry(capacity=2)
        registry.activate(self.snapshot(epoch=2, host="*.example.com"))
        old = self.admit(registry, sni="docs.example.com")

        with self.assertRaises(registry_module.RegistryError):
            registry.activate(self.snapshot(epoch=1, host="api.example.com"))

        self.assertEqual(registry.count, 1)
        other = self.admit(registry, sni="other.example.com")
        self.assertEqual(other.action, "decrypt")
        self.assertEqual(registry.activate(
            self.snapshot(epoch=3, host="api.example.com")),
            (old.token, other.token))

    def test_invalid_snapshot_does_not_replace_active_view(self):
        registry = registry_module.BoundConnectionRegistry(capacity=2)
        registry.activate(self.snapshot(host="*.example.com"))
        old = self.admit(registry, sni="docs.example.com")
        candidate = self.snapshot(epoch=2, host="api.example.com")
        invalid = receiver.Snapshot(candidate.revision, b"invalid snapshot")

        with self.assertRaises(registry_module.RegistryError):
            registry.activate(invalid)

        self.assertEqual(registry.count, 1)
        other = self.admit(registry, sni="other.example.com")
        self.assertEqual(other.action, "decrypt")
        self.assertEqual(registry.activate(candidate),
                         (old.token, other.token))

    def test_admission_racing_with_cutover_is_either_reported_or_passthrough(self):
        old = self.snapshot(host="*.example.com")
        new = self.snapshot(epoch=2, host="api.example.com")
        for _ in range(24):
            registry = registry_module.BoundConnectionRegistry(capacity=1)
            registry.activate(old)
            start = threading.Barrier(3)

            def admit():
                start.wait()
                return self.admit(registry, sni="docs.example.com")

            def cutover():
                start.wait()
                return registry.activate(new)

            with ThreadPoolExecutor(max_workers=2) as pool:
                admitted = pool.submit(admit)
                transitioned = pool.submit(cutover)
                start.wait()
                result = admitted.result(timeout=2)
                uncovered = transitioned.result(timeout=2)

            if result.action == "decrypt":
                self.assertEqual(uncovered, (result.token,))
            else:
                self.assertEqual((result.action, result.reason, uncovered),
                                 ("passthrough", "no_binding_host", ()))


if __name__ == "__main__":
    unittest.main()

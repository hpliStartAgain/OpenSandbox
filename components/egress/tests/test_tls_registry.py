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
import traceback
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

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


class ObservedLock:
    """A real mutex with test-only events at entry and before publication unlock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.attempted = threading.Event()
        self.before_unlock = threading.Event()
        self.resume = threading.Event()
        self.pause_next_exit = False

    def __enter__(self):
        self.attempted.set()
        self.lock.acquire()
        return self

    def __exit__(self, *args):
        try:
            if self.pause_next_exit:
                self.pause_next_exit = False
                self.before_unlock.set()
                if not self.resume.wait(5):
                    raise AssertionError("publication unlock timed out")
        finally:
            self.lock.release()

    def locked(self):
        return self.lock.locked()


class TLSRegistryTest(unittest.TestCase):
    identity = ("control-a", "subject-a")

    def snapshot(
        self, epoch=1, host="api.example.com", identity=None, *, secret="",
        methods=("GET",), paths=("/api/*",), vault_revision=None, policy_epoch=1,
    ):
        control, subject = identity or self.identity
        hosts = list(host) if type(host) is tuple else ([] if host is None else [host])
        bindings = [] if host is None else [{
            "name": "binding-a",
            "match": {
                "schemes": ["https"],
                "hosts": hosts,
                "methods": list(methods),
                "paths": list(paths),
            },
            "headers": [] if not secret else [{"name": "Private-Token", "value": secret}],
        }]
        payload = {
            "version": 1,
            "vaultRevision": (1 if bindings else 0) if vault_revision is None else vault_revision,
            "effectivePolicyEpoch": policy_epoch,
            "interceptionMode": "credential-bound",
            "state": "active" if bindings else "active-empty",
            "tlsBindingHostSelectors": sorted(hosts),
            "fullRenderedBindings": bindings,
            "redactions": [] if not secret else [secret],
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        revision = receiver.Revision(
            control, subject, epoch, payload["vaultRevision"], policy_epoch,
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


class TLSRequestAdmissionTest(unittest.TestCase):
    identity = TLSRegistryTest.identity
    snapshot = TLSRegistryTest.snapshot
    admit = TLSRegistryTest.admit

    def new_receiver(self, snapshot=None):
        identity = self.identity if snapshot is None else (
            snapshot.revision.control_generation, snapshot.revision.subject_generation,
        )
        active = receiver.Receiver(*identity, decision.validate, max_snapshot_bytes=65536)
        if snapshot is not None:
            self.commit(active, snapshot)
        return active

    def commit(self, active, snapshot):
        active.prepare(snapshot.revision, snapshot.payload)
        active.commit(snapshot.revision)

    def setup_registry(self, snapshot=None, *, capacity=4):
        snapshot = self.snapshot() if snapshot is None else snapshot
        active = self.new_receiver(snapshot)
        registry = registry_module.BoundConnectionRegistry(capacity=capacity, receiver=active)
        registry.activate(snapshot)
        return registry, active

    def assert_denied(self, registry, token, reason):
        result = registry.acquire_request(token)
        self.assertEqual((result.action, result.reason, result.snapshot), ("deny", reason, None))

    def test_allow_pins_real_immutable_snapshot(self):
        registry, active = self.setup_registry(self.snapshot(secret="canaryCredential"))
        result = registry.acquire_request(self.admit(registry).token)
        self.assertEqual((result.action, result.reason), ("allow", "admitted"))
        self.assertIs(result.snapshot, active.acquire())
        self.assertIs(type(result.snapshot.payload), bytes)
        for target, attribute, value in (
            (result, "action", "deny"),
            (result.snapshot, "payload", b"changed"),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(target, attribute, value)
        self.assertFalse(hasattr(result, "__dict__"))
        self.assertNotIn("canaryCredential", repr(result))
        self.assertNotIn("api.example.com", repr(result))

    def test_remove_readd_never_revives_old_token(self):
        registry, active = self.setup_registry()
        old = self.admit(registry).token
        removed = self.snapshot(epoch=2, host=None)
        self.assertEqual(registry.activate(removed), (old,))
        self.commit(active, removed)
        self.assert_denied(registry, old, "connection_fenced")
        restored = self.snapshot(epoch=3)
        self.commit(active, restored)
        self.assertEqual(registry.activate(restored), ())
        self.assert_denied(registry, old, "connection_fenced")
        new = self.admit(registry).token
        self.assertNotEqual(new.serial, old.serial)
        self.assertEqual(registry.acquire_request(new).action, "allow")
        self.assertEqual(registry.activate(self.snapshot(epoch=4, host=None)), (old, new))
        self.assert_denied(registry, old, "connection_fenced")

    def test_mutable_snapshot_payload_is_rejected(self):
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        snapshot = self.snapshot()
        with self.assertRaises(registry_module.RegistryError):
            registry.activate(receiver.Snapshot(snapshot.revision, bytearray(snapshot.payload)))

    def test_request_requires_exact_live_token_without_hashing_bad_serials(self):
        registry, _ = self.setup_registry()
        token = self.admit(registry).token
        other, _ = self.setup_registry()
        foreign = self.admit(other).token

        class BadHash(int):
            def __hash__(self):
                raise AssertionError("must not hash untrusted serial")

        class TokenSubclass(registry_module.AdmissionToken):
            pass

        candidates = (
            None, object(), {}, foreign, replace(token),
            replace(token, serial=[]), replace(token, serial=True),
            replace(token, serial=BadHash(token.serial)),
            replace(token, revision=self.snapshot(epoch=2).revision),
            TokenSubclass(token.serial, token.revision, token.sni, token.owner),
        )
        for candidate in candidates:
            with self.subTest(candidate_type=type(candidate).__name__):
                self.assert_denied(registry, candidate, "invalid_token")
        self.assertEqual(registry.acquire_request(token).action, "allow")
        self.assertTrue(registry.release(token))
        self.assert_denied(registry, token, "invalid_token")

    def test_receiver_is_bound_once_and_missing_or_replaced_receivers_deny(self):
        snapshot = self.snapshot()
        registry = registry_module.BoundConnectionRegistry(capacity=1)
        registry.activate(snapshot)
        self.assert_denied(registry, self.admit(registry).token, "snapshot_missing")
        active = self.new_receiver()
        registry = registry_module.BoundConnectionRegistry(capacity=1, receiver=active)
        registry.activate(snapshot)
        token = self.admit(registry).token
        self.assert_denied(registry, token, "snapshot_missing")
        self.commit(active, snapshot)
        self.assertEqual(registry.acquire_request(token).action, "allow")
        replacement, _ = self.setup_registry(snapshot)
        self.assert_denied(replacement, token, "invalid_token")
        self.assertFalse(hasattr(registry, "rebind"))
        with self.assertRaises(TypeError):
            registry.acquire_request(token, receiver=self.new_receiver(snapshot))

        class ReceiverSubclass(receiver.Receiver):
            pass

        wrong = ReceiverSubclass(*self.identity, decision.validate, max_snapshot_bytes=65536)
        for value in (object(), lambda: snapshot, wrong):
            with self.subTest(receiver_type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, "^TLS registry receiver required$"):
                    registry_module.BoundConnectionRegistry(capacity=1, receiver=value)

    def test_both_publication_orders_deny_until_revisions_agree(self):
        for receiver_first in (True, False):
            with self.subTest(receiver_first=receiver_first):
                registry, active = self.setup_registry()
                token = self.admit(registry).token
                new = self.snapshot(epoch=2)
                if receiver_first:
                    self.commit(active, new)
                else:
                    registry.activate(new)
                self.assert_denied(registry, token, "snapshot_mismatch")
                if receiver_first:
                    registry.activate(new)
                else:
                    self.commit(active, new)
                self.assertIs(registry.acquire_request(token).snapshot, active.acquire())

    def test_full_revision_identity_is_required_even_at_same_epoch(self):
        original = self.snapshot()
        variants = (
            self.snapshot(epoch=2),
            self.snapshot(secret="differentDigest"),
            self.snapshot(vault_revision=2),
            self.snapshot(policy_epoch=2),
            self.snapshot(identity=("control-b", "subject-a")),
            self.snapshot(identity=("control-a", "subject-b")),
        )
        for variant in variants:
            with self.subTest(revision=variant.revision):
                active = self.new_receiver(variant)
                registry = registry_module.BoundConnectionRegistry(capacity=1, receiver=active)
                registry.activate(original)
                self.assert_denied(registry, self.admit(registry).token, "snapshot_mismatch")

    def test_rotation_and_request_selectors_keep_token_but_pin_new_snapshot(self):
        for change in (
            {"secret": "newCredential", "vault_revision": 2},
            {"methods": ("POST",)},
            {"paths": ("/changed/*",)},
        ):
            with self.subTest(change=change):
                original = self.snapshot(secret="oldCredential")
                registry, active = self.setup_registry(original)
                token = self.admit(registry).token
                old_request = registry.acquire_request(token)
                kwargs = {"secret": "oldCredential", **change}
                new = self.snapshot(epoch=2, **kwargs)
                self.commit(active, new)
                self.assertEqual(registry.activate(new), ())
                new_request = registry.acquire_request(token)
                self.assertEqual(new_request.action, "allow")
                self.assertIs(new_request.snapshot, active.acquire())
                self.assertEqual(new_request.snapshot.payload, new.payload)
                self.assertEqual(old_request.snapshot.payload, original.payload)
                for request, secret in (
                    (old_request, "oldCredential"),
                    (new_request, kwargs["secret"]),
                ):
                    payload = json.loads(request.snapshot.payload)
                    header = payload["fullRenderedBindings"][0]["headers"][0]
                    self.assertEqual(header["value"], secret)
                    self.assertEqual(payload["redactions"], [secret])
                self.assertEqual(registry._request_fenced, set())

    def test_semantic_coverage_fences_only_truly_uncovered_hosts(self):
        cases = (
            ("*.example.com", "api.example.com", ("allow", "deny")),
            ("api.example.com", "*.example.com", ("allow",)),
            (("*.example.com", "api.example.com"), "*.example.com", ("allow", "allow")),
            ("*.example.com", None, ("deny", "deny")),
        )
        for previous, new_host, expected in cases:
            with self.subTest(previous=previous, new=new_host):
                registry, active = self.setup_registry(self.snapshot(host=previous))
                tokens = [self.admit(registry, sni="API.EXAMPLE.COM.").token]
                if len(expected) == 2:
                    tokens.append(self.admit(registry, sni="docs.example.com").token)
                new = self.snapshot(epoch=2, host=new_host)
                self.commit(active, new)
                uncovered = registry.activate(new)
                self.assertEqual(uncovered, tuple(
                    token for token, action in zip(tokens, expected) if action == "deny"
                ))
                for token, action in zip(tokens, expected):
                    result = registry.acquire_request(token)
                    self.assertEqual(result.action, action)
                    if action == "deny":
                        self.assertIsNone(result.snapshot)
                        self.assertEqual(result.reason, "connection_fenced")

    def test_rejected_activation_keeps_view_members_and_fences_unchanged(self):
        registry, _ = self.setup_registry(self.snapshot(host="*.example.com"))
        docs = self.admit(registry, sni="docs.example.com").token
        api = self.admit(registry).token
        current = self.snapshot(epoch=2)
        registry.activate(current)
        view, generation = registry._view, registry._generation
        entries = dict(registry._entries)
        fenced = set(registry._request_fenced)
        candidate = self.snapshot(epoch=3, secret="canaryCredential")

        class RevisionLike:
            def __getattr__(self, name):
                return getattr(candidate.revision, name)

            def __eq__(self, other):
                raise AssertionError("canaryCredential")

        class RevisionSubclass(receiver.Revision):
            pass

        class BytesSubclass(bytes):
            pass

        invalid = (
            self.snapshot(epoch=1),
            self.snapshot(epoch=2, host=None),
            self.snapshot(epoch=3, identity=("control-b", "subject-a")),
            self.snapshot(epoch=3, identity=("control-a", "subject-b")),
            receiver.Snapshot(candidate.revision, b"canaryCredential"),
            receiver.Snapshot(candidate.revision, bytearray(candidate.payload)),
            receiver.Snapshot(candidate.revision, BytesSubclass(candidate.payload)),
            receiver.Snapshot(RevisionLike(), candidate.payload),
            receiver.Snapshot(RevisionSubclass(
                *self.identity, 3, 1, 1, candidate.revision.digest,
            ), candidate.payload),
        )
        for snapshot in invalid:
            with self.subTest(snapshot_type=type(snapshot.payload).__name__):
                try:
                    registry.activate(snapshot)
                except registry_module.RegistryError as error:
                    self.assertEqual(str(error), "invalid TLS registry activation")
                    self.assertIsNone(error.__context__)
                    self.assertNotIn("canaryCredential", traceback.format_exception(error)[-1])
                else:
                    self.fail("invalid snapshot accepted")
                self.assertIs(registry._view, view)
                self.assertEqual(registry._generation, generation)
                self.assertEqual(registry._entries, entries)
                self.assertEqual(registry._request_fenced, fenced)
        self.assertEqual(fenced, {docs.serial})
        self.assertNotIn(api.serial, fenced)

    def test_release_reclaims_fence_budget_and_serials_never_repeat(self):
        registry, active = self.setup_registry(capacity=1)
        last_serial = 0
        for index in range(20):
            token = self.admit(registry).token
            self.assertGreater(token.serial, last_serial)
            last_serial = token.serial
            removed = self.snapshot(epoch=2 * index + 2, host=None)
            self.commit(active, removed)
            registry.activate(removed)
            self.assertEqual(registry._request_fenced, {token.serial})
            self.assertEqual(registry.count, 1)
            restored = self.snapshot(epoch=2 * index + 3)
            self.commit(active, restored)
            registry.activate(restored)
            self.assertEqual(self.admit(registry).reason, "registry_exhausted")
            self.assertTrue(registry.release(token))
            self.assertFalse(registry.release(token))
            self.assertEqual(registry.count, 0)
            self.assertEqual(registry._request_fenced, set())
            self.assert_denied(registry, token, "invalid_token")

    def test_close_and_deactivate_deny_new_requests_but_preserve_old_snapshot(self):
        for operation, reason in (
            ("close", "receiver_unavailable"), ("deactivate", "registry_closed"),
        ):
            with self.subTest(operation=operation):
                registry, active = self.setup_registry(self.snapshot(secret="oldCredential"))
                token = self.admit(registry).token
                request = registry.acquire_request(token)
                if operation == "close":
                    active.close()
                else:
                    self.assertEqual(registry.deactivate(), (token,))
                    self.assertEqual(registry.deactivate(), (token,))
                    self.assertIs(active.acquire(), request.snapshot)
                    with self.assertRaises(registry_module.RegistryError):
                        registry.activate(self.snapshot(epoch=2))
                self.assert_denied(registry, token, reason)
                self.assertIn(b"oldCredential", request.snapshot.payload)
                self.assertTrue(registry.release(token))
                self.assertIn(b"oldCredential", request.snapshot.payload)

    def test_receiver_failure_is_sanitized_without_old_snapshot_fallback(self):
        registry, active = self.setup_registry(self.snapshot(secret="canaryCredential"))
        token = self.admit(registry).token
        old = registry.acquire_request(token)
        error = RuntimeError("api.example.com canaryCredential")
        with patch.object(active, "acquire", side_effect=error):
            result = registry.acquire_request(token)
        self.assertEqual((result.action, result.reason, result.snapshot),
                         ("deny", "receiver_unavailable", None))
        self.assertNotIn("canaryCredential", repr(result))
        self.assertNotIn("api.example.com", repr(result))
        self.assertIsNotNone(old.snapshot)

    def test_request_holds_registry_lock_before_and_after_receiver_pin(self):
        # Both pause locations catch check -> unlock -> acquire implementations.
        for pinned in (False, True):
            for operation in ("remove", "release", "deactivate"):
                with self.subTest(pinned=pinned, operation=operation):
                    registry, active = self.setup_registry()
                    token = self.admit(registry).token
                    old = active.acquire()
                    entered, resume = threading.Event(), threading.Event()
                    mutex = ObservedLock()
                    registry._lock = mutex
                    acquire = active.acquire

                    def paused_acquire():
                        snapshot = acquire() if pinned else None
                        entered.set()
                        if not resume.wait(5):
                            raise AssertionError("request pin timed out")
                        return snapshot if pinned else acquire()

                    def mutate():
                        if operation == "remove":
                            return registry.activate(self.snapshot(epoch=2, host=None))
                        if operation == "release":
                            return registry.release(token)
                        return registry.deactivate()

                    with patch.object(active, "acquire", paused_acquire):
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            request = pool.submit(registry.acquire_request, token)
                            try:
                                self.assertTrue(entered.wait(5))
                                self.assertTrue(mutex.locked())
                                mutex.attempted.clear()
                                mutation = pool.submit(mutate)
                                self.assertTrue(mutex.attempted.wait(5))
                                self.assertFalse(mutation.done())
                            finally:
                                resume.set()
                            result = request.result(timeout=5)
                            mutation.result(timeout=5)
                    self.assertEqual(result.action, "allow")
                    self.assertIs(result.snapshot, old)
                    reason = {
                        "remove": "connection_fenced", "release": "invalid_token",
                        "deactivate": "registry_closed",
                    }[operation]
                    self.assert_denied(registry, token, reason)

    def test_published_fence_release_or_close_wins_before_request_checks(self):
        for operation in ("remove", "release", "deactivate"):
            with self.subTest(operation=operation):
                registry, active = self.setup_registry()
                token = self.admit(registry).token
                mutex = ObservedLock()
                registry._lock = mutex
                mutex.pause_next_exit = True

                def mutate():
                    if operation == "remove":
                        return registry.activate(self.snapshot(epoch=2, host=None))
                    if operation == "release":
                        return registry.release(token)
                    return registry.deactivate()

                with patch.object(active, "acquire", wraps=active.acquire) as acquire:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        mutation = pool.submit(mutate)
                        try:
                            self.assertTrue(mutex.before_unlock.wait(5))
                            mutex.attempted.clear()
                            request = pool.submit(registry.acquire_request, token)
                            self.assertTrue(mutex.attempted.wait(5))
                            self.assertFalse(request.done())
                        finally:
                            mutex.resume.set()
                        mutation.result(timeout=5)
                        result = request.result(timeout=5)
                    acquire.assert_not_called()
                reason = {
                    "remove": "connection_fenced", "release": "invalid_token",
                    "deactivate": "registry_closed",
                }[operation]
                self.assertEqual((result.action, result.reason, result.snapshot),
                                 ("deny", reason, None))

    def test_receiver_commit_and_close_before_or_after_pin(self):
        for pinned in (False, True):
            for operation in ("commit", "close"):
                with self.subTest(pinned=pinned, operation=operation):
                    registry, active = self.setup_registry()
                    token = self.admit(registry).token
                    old = active.acquire()
                    new = self.snapshot(epoch=2)
                    if operation == "commit":
                        active.prepare(new.revision, new.payload)
                    entered, resume = threading.Event(), threading.Event()
                    acquire = active.acquire

                    def paused_acquire():
                        snapshot = acquire() if pinned else None
                        entered.set()
                        if not resume.wait(5):
                            raise AssertionError("receiver pin timed out")
                        return snapshot if pinned else acquire()

                    with patch.object(active, "acquire", paused_acquire):
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            request = pool.submit(registry.acquire_request, token)
                            try:
                                self.assertTrue(entered.wait(5))
                                if operation == "commit":
                                    mutation = pool.submit(active.commit, new.revision)
                                else:
                                    mutation = pool.submit(active.close)
                                # Receiver state can advance while Registry stays locked.
                                mutation.result(timeout=5)
                            finally:
                                resume.set()
                            result = request.result(timeout=5)
                    if pinned:
                        self.assertEqual(result.action, "allow")
                        self.assertIs(result.snapshot, old)
                    else:
                        reason = (
                            "snapshot_mismatch" if operation == "commit"
                            else "receiver_unavailable"
                        )
                        self.assertEqual((result.action, result.reason, result.snapshot),
                                         ("deny", reason, None))

    def test_request_before_view_publication_denies_receiver_ahead(self):
        registry, active = self.setup_registry()
        token = self.admit(registry).token
        new = self.snapshot(epoch=2)
        self.commit(active, new)
        entered, resume = threading.Event(), threading.Event()
        compile_view = registry_module.compile_view

        def paused_compile(snapshot):
            view = compile_view(snapshot)
            entered.set()
            if not resume.wait(5):
                raise AssertionError("view compilation timed out")
            return view

        with patch.object(registry_module, "compile_view", paused_compile):
            with ThreadPoolExecutor(max_workers=1) as pool:
                publication = pool.submit(registry.activate, new)
                try:
                    self.assertTrue(entered.wait(5))
                    self.assert_denied(registry, token, "snapshot_mismatch")
                finally:
                    resume.set()
                publication.result(timeout=5)
        self.assertIs(registry.acquire_request(token).snapshot, active.acquire())

    def test_slow_old_compilation_cannot_replace_new_view_or_fences(self):
        registry, active = self.setup_registry()
        token = self.admit(registry).token
        slow, latest = self.snapshot(epoch=2), self.snapshot(epoch=3, host=None)
        entered, resume = threading.Event(), threading.Event()
        compile_view = registry_module.compile_view

        def paused_compile(snapshot):
            view = compile_view(snapshot)
            if snapshot is slow:
                entered.set()
                if not resume.wait(5):
                    raise AssertionError("old compilation timed out")
            return view

        with patch.object(registry_module, "compile_view", paused_compile):
            with ThreadPoolExecutor(max_workers=1) as pool:
                publication = pool.submit(registry.activate, slow)
                try:
                    self.assertTrue(entered.wait(5))
                    self.commit(active, latest)
                    self.assertEqual(registry.activate(latest), (token,))
                    view = registry._view
                finally:
                    resume.set()
                with self.assertRaises(registry_module.RegistryError):
                    publication.result(timeout=5)
        self.assertIs(registry._view, view)
        self.assertEqual(registry._request_fenced, {token.serial})
        self.assert_denied(registry, token, "connection_fenced")


if __name__ == "__main__":
    unittest.main()

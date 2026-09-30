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

"""Unused sidecar-only admission foundation for credential-bound TLS.

The future addon integration must publish the receiver's confirmed view under
the same mutation barrier that installs request fences. Publishing a view here
alone neither closes old connections nor authorizes a public mutation ACK.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Literal

from host_selectors import Selector
from revision_receiver import Receiver, Revision, Snapshot
from tls_decision import Generation, Reason, TLSSelectorView, classify, compile_view

RegistryAction = Literal["deny", "passthrough", "decrypt"]
RegistryReason = Reason | Literal["registry_exhausted"]
RequestReason = Literal[
    "admitted",
    "invalid_token",
    "connection_fenced",
    "registry_closed",
    "snapshot_missing",
    "snapshot_mismatch",
    "receiver_unavailable",
]


class RegistryError(Exception):
    """A fixed activation error that never contains snapshot data."""


@dataclass(frozen=True, slots=True)
class AdmissionToken:
    """Opaque connection membership; retain it until the connection closes."""

    serial: int
    revision: Revision
    sni: str = field(repr=False)
    owner: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    action: RegistryAction
    reason: RegistryReason
    token: AdmissionToken | None = None


@dataclass(frozen=True, slots=True)
class RequestAdmission:
    """Request lifecycle eligibility, not authorization to inject credentials."""

    action: Literal["allow", "deny"]
    reason: RequestReason
    snapshot: Snapshot | None = field(default=None, repr=False)


class BoundConnectionRegistry:
    """Atomically classify and admit only bound sidecar TLS connections.

    This registry owns no sockets. The caller must close or fence tracked
    connections before acknowledging a host-removal or generation transition.
    """

    def __init__(self, *, capacity: int, receiver: Receiver | None = None) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("positive TLS registry capacity required")
        if receiver is not None and type(receiver) is not Receiver:
            raise TypeError("TLS registry receiver required")
        self._capacity = capacity
        self._receiver = receiver
        self._lock = threading.Lock()
        self._owner = object()
        self._view: TLSSelectorView | None = None
        self._generation: Generation | None = None
        self._closed = False
        self._entries: dict[int, AdmissionToken] = {}
        self._request_fenced: set[int] = set()
        self._next_serial = 0

    def activate(self, snapshot: Snapshot) -> tuple[AdmissionToken, ...]:
        """Publish a confirmed snapshot and return newly uncovered memberships.

        Newly uncovered members are permanently fenced from new requests.
        The result still identifies transports for a future owner to drain;
        this method neither closes them nor authorizes a mutation ACK.
        """
        if (
            type(snapshot) is not Snapshot
            or type(snapshot.revision) is not Revision
            or type(snapshot.payload) is not bytes
        ):
            raise RegistryError("invalid TLS registry activation")
        valid = True
        try:
            view = compile_view(snapshot)
        except Exception:  # noqa: BLE001 - snapshot errors may contain credentials
            valid = False
        if not valid:
            raise RegistryError("invalid TLS registry activation")
        with self._lock:
            previous = self._view
            newly_uncovered: tuple[AdmissionToken, ...] = ()
            new = view.revision
            new_generation = (new.control_generation, new.subject_generation)
            if self._closed or self._generation not in (None, new_generation):
                raise RegistryError("invalid TLS registry activation")
            if previous is not None:
                old = previous.revision
                if new.decision_epoch < old.decision_epoch or (
                    new.decision_epoch == old.decision_epoch and view != previous
                ):
                    raise RegistryError("invalid TLS registry activation")
                newly_uncovered = tuple(
                    token for token in self._entries.values()
                    if any(selector.matches(token.sni) for selector in previous.selectors)
                    and not any(selector.matches(token.sni) for selector in view.selectors)
                )
            fenced = self._request_fenced.union(token.serial for token in newly_uncovered)
            self._view = view
            self._generation = new_generation
            self._request_fenced = fenced
            return newly_uncovered

    def deactivate(self) -> tuple[AdmissionToken, ...]:
        """Fence future decisions and hand existing memberships to the owner.

        The caller must close those transports and release their tokens. This
        method does not close sockets or permit this registry to resume.
        """
        with self._lock:
            self._closed = True
            self._view = None
            return tuple(self._entries.values())

    def admit(
        self,
        *,
        identity: Generation | None,
        sni: str | None,
        ech_hidden: bool,
        static_passthrough: tuple[Selector, ...],
    ) -> AdmissionResult:
        """Recheck the active epoch and capacity in one critical section."""
        with self._lock:
            result = classify(
                identity=identity,
                sni=sni,
                ech_hidden=ech_hidden,
                static_passthrough=static_passthrough,
                view=self._view,
            )
            if result.action != "needs_registry":
                return AdmissionResult(result.action, result.reason)
            if len(self._entries) >= self._capacity:
                return AdmissionResult("deny", "registry_exhausted")
            self._next_serial += 1
            # classify only returns needs_registry for a valid, nonempty SNI
            # and a matching installed view.
            assert self._view is not None and sni is not None
            token = AdmissionToken(
                self._next_serial,
                self._view.revision,
                sni.lower().removesuffix("."),
                self._owner,
            )
            self._entries[token.serial] = token
            return AdmissionResult("decrypt", "binding_host", token)

    def acquire_request(self, token: AdmissionToken | None) -> RequestAdmission:
        """Pin one coherent snapshot while connection eligibility is stable.

        Lock order is Registry -> Receiver. The receiver must never call back
        into this registry while holding its state lock. A successful request
        is admitted when Receiver.acquire pins its snapshot, even if commit or
        close happens before this method returns. Its caller must retain that
        same snapshot through binding checks, injection and response redaction.

        Independent Receiver/Registry publications may temporarily deny requests;
        this primitive is not their joint commit or a transport drain owner.
        """
        with self._lock:
            if (
                type(token) is not AdmissionToken
                or token.owner is not self._owner
                or type(token.serial) is not int
                or self._entries.get(token.serial) is not token
            ):
                return RequestAdmission("deny", "invalid_token")
            if self._closed:
                return RequestAdmission("deny", "registry_closed")
            if token.serial in self._request_fenced:
                return RequestAdmission("deny", "connection_fenced")
            if self._view is None or self._receiver is None:
                return RequestAdmission("deny", "snapshot_missing")
            born = token.revision
            current = self._view.revision
            if (born.control_generation, born.subject_generation) != (
                current.control_generation, current.subject_generation
            ):
                return RequestAdmission("deny", "invalid_token")
            try:
                snapshot = self._receiver.acquire()
            except Exception:  # noqa: BLE001 - never expose receiver error contents
                return RequestAdmission("deny", "receiver_unavailable")
            if snapshot is None:
                return RequestAdmission("deny", "snapshot_missing")
            if snapshot.revision != current:
                return RequestAdmission("deny", "snapshot_mismatch")
            return RequestAdmission("allow", "admitted", snapshot)

    def release(self, token: AdmissionToken | None) -> bool:
        """Idempotently remove an exact admission; serials are never reused."""
        if type(token) is not AdmissionToken or token.owner is not self._owner:
            return False
        with self._lock:
            if self._entries.get(token.serial) != token:
                return False
            del self._entries[token.serial]
            self._request_fenced.discard(token.serial)
            return True

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

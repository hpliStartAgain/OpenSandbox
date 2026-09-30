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
    "request_registry_exhausted",
]


class RegistryError(Exception):
    """A fixed registry error that never contains snapshot data."""


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
class PendingRequest:
    """Internal metadata only; neither a finish capability nor proof of drain."""

    serial: int
    connection_serial: int
    revision: Revision


@dataclass(frozen=True, slots=True, eq=False)
class RequestHandle:
    """Exact in-process request membership; finish on every terminal path."""

    serial: int
    owner: object = field(repr=False)
    connection: AdmissionToken = field(repr=False)
    snapshot: Snapshot = field(repr=False)

    @property
    def revision(self) -> Revision:
        return self.snapshot.revision


@dataclass(frozen=True, slots=True)
class RequestAdmission:
    """Request lifecycle eligibility, not authorization to inject credentials."""

    action: Literal["allow", "deny"]
    reason: RequestReason
    snapshot: Snapshot | None = field(default=None, repr=False)
    handle: RequestHandle | None = field(default=None, repr=False)


class BoundConnectionRegistry:
    """Atomically classify and admit only bound sidecar TLS connections.

    This registry owns no sockets. The caller must close or fence tracked
    connections before acknowledging a host-removal or generation transition.
    """

    def __init__(
        self, *, capacity: int, receiver: Receiver | None = None,
        request_capacity: int | None = None,
    ) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("positive TLS registry capacity required")
        if receiver is not None and type(receiver) is not Receiver:
            raise TypeError("TLS registry receiver required")
        if request_capacity is None:
            request_capacity = capacity
        if type(request_capacity) is not int or request_capacity <= 0:
            raise ValueError("positive request registry capacity required")
        self._capacity = capacity
        # This compatibility default is not a production HTTP/2 sizing policy.
        self._request_capacity = request_capacity
        self._receiver = receiver
        self._lock = threading.Lock()
        self._owner = object()
        self._view: TLSSelectorView | None = None
        self._generation: Generation | None = None
        self._closed = False
        self._entries: dict[int, AdmissionToken] = {}
        self._request_fenced: set[int] = set()
        self._next_serial = 0
        self._requests: dict[int, RequestHandle] = {}
        self._requests_by_connection: dict[int, set[int]] = {}
        self._next_request_serial = 0

    def _owns_connection(self, token: AdmissionToken | None) -> bool:
        """Check exact membership with the Registry lock already held."""
        return (
            type(token) is AdmissionToken
            and token.owner is self._owner
            and type(token.serial) is int
            and self._entries.get(token.serial) is token
        )

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
        """Pin and register one snapshot while connection eligibility is stable.

        Lock order is Registry -> Receiver. The receiver must never call back
        into this registry while holding its state lock. A successful request
        is admitted when Receiver.acquire pins its snapshot, even if commit or
        close happens before this method returns. Its caller must retain that
        same snapshot through binding checks, injection and response redaction.
        The caller must finish its handle in every completion/cancellation/error
        path. Terminal connection release also removes its request records, but
        does not revoke external handles or cancel work still using them.

        Independent Receiver/Registry publications may temporarily deny requests;
        this primitive is not their joint commit or a transport drain owner.
        """
        with self._lock:
            if not self._owns_connection(token):
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
            if len(self._requests) >= self._request_capacity:
                return RequestAdmission("deny", "request_registry_exhausted")
            try:
                snapshot = self._receiver.acquire()
            except Exception:  # noqa: BLE001 - never expose receiver error contents
                return RequestAdmission("deny", "receiver_unavailable")
            if snapshot is None:
                return RequestAdmission("deny", "snapshot_missing")
            if snapshot.revision != current:
                return RequestAdmission("deny", "snapshot_mismatch")
            serial = self._next_request_serial + 1
            handle = RequestHandle(serial, self._owner, token, snapshot)
            result = RequestAdmission("allow", "admitted", snapshot, handle)
            members = self._requests_by_connection.get(token.serial)
            if members is None:
                members = set()
            self._next_request_serial = serial
            registered = True
            try:
                self._requests[serial] = handle
                self._requests_by_connection[token.serial] = members
                members.add(serial)
            except Exception:  # noqa: BLE001 - roll back without exposing payloads
                self._requests.pop(serial, None)
                members.discard(serial)
                if not members:
                    self._requests_by_connection.pop(token.serial, None)
                registered = False
            if not registered:
                # Raise outside the handler: no secret-bearing exception context.
                raise RegistryError("request registration failed")
            return result

    def finish_request(self, handle: RequestHandle | None) -> bool:
        """Idempotently remove an exact live request, leaving its connection open."""
        with self._lock:
            if (
                type(handle) is not RequestHandle
                or handle.owner is not self._owner
                or type(handle.serial) is not int
                or self._requests.get(handle.serial) is not handle
            ):
                return False
            del self._requests[handle.serial]
            connection_serial = handle.connection.serial
            members = self._requests_by_connection[connection_serial]
            members.remove(handle.serial)
            if not members:
                del self._requests_by_connection[connection_serial]
            return True

    def release(self, token: AdmissionToken | None) -> bool:
        """Remove an exact terminal connection and all of its request records.

        Only call after the transport owner confirms terminal state, not to start
        drain. This clears accounting, not external references or running work.
        A request admitted first may return its handle after terminal release.
        """
        with self._lock:
            if not self._owns_connection(token):
                return False
            for serial in self._requests_by_connection.pop(token.serial, ()):
                del self._requests[serial]
            del self._entries[token.serial]
            self._request_fenced.discard(token.serial)
            return True

    def pending_requests(
        self, *, connection: AdmissionToken | None = None,
        revision: Revision | None = None, after_serial: int = 0, limit: int = 128,
    ) -> tuple[PendingRequest, ...]:
        """Return a bounded metadata page, without snapshots or finish handles.

        Each page is consistent under the lock; pages are not a frozen view.
        Completions can disappear and new admissions can appear between pages.
        The last returned serial is the next cursor. Empty is not proof of
        transport drain or permission to acknowledge a public mutation.
        """
        if (
            type(after_serial) is not int or after_serial < 0
            or type(limit) is not int or not 1 <= limit <= 128
            or revision is not None and type(revision) is not Revision
        ):
            raise ValueError("invalid pending request query")
        with self._lock:
            if connection is not None and not self._owns_connection(connection):
                return ()
            result = []
            # Dict insertion order is serial order; serials are never reused.
            for serial, handle in self._requests.items():
                if (
                    serial <= after_serial
                    or connection is not None and handle.connection is not connection
                    or revision is not None and handle.revision != revision
                ):
                    continue
                result.append(PendingRequest(serial, handle.connection.serial, handle.revision))
                if len(result) == limit:
                    break
            return tuple(result)

    @property
    def request_count(self) -> int:
        """Registry-held records only, not all externally retained snapshots."""
        with self._lock:
            return len(self._requests)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

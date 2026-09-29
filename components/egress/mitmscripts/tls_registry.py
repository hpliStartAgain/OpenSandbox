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
from revision_receiver import Revision, Snapshot
from tls_decision import Generation, Reason, TLSSelectorView, classify, compile_view

RegistryAction = Literal["deny", "passthrough", "decrypt"]
RegistryReason = Reason | Literal["registry_exhausted"]


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


class BoundConnectionRegistry:
    """Atomically classify and admit only bound sidecar TLS connections.

    This registry owns no sockets. The caller must close or fence tracked
    connections before acknowledging a host-removal or generation transition.
    """

    def __init__(self, *, capacity: int) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("positive TLS registry capacity required")
        self._capacity = capacity
        self._lock = threading.Lock()
        self._owner = object()
        self._view: TLSSelectorView | None = None
        self._generation: Generation | None = None
        self._closed = False
        self._entries: dict[int, AdmissionToken] = {}
        self._next_serial = 0

    def activate(self, snapshot: Snapshot) -> None:
        """Validate and publish a confirmed snapshot for this one generation."""
        if type(snapshot) is not Snapshot:
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
            self._view = view
            self._generation = new_generation

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

    def release(self, token: AdmissionToken | None) -> bool:
        """Idempotently remove an exact admission; serials are never reused."""
        if type(token) is not AdmissionToken or token.owner is not self._owner:
            return False
        with self._lock:
            if self._entries.get(token.serial) != token:
                return False
            del self._entries[token.serial]
            return True

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

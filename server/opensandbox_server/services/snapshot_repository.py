# Copyright 2025 Alibaba Group Holding Ltd.
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

"""
Repository abstraction for persisted snapshot records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

from opensandbox_server.services.snapshot_models import SnapshotRecord, SnapshotState


@dataclass(slots=True)
class SnapshotListQuery:
    """
    Filtering and pagination options for listing snapshot records.
    """

    page: int = 1
    page_size: int = 20
    source_sandbox_id: str | None = None
    name: str | None = None
    states: list[str] = field(default_factory=list)
    namespace: str | None = None


@dataclass(slots=True)
class SnapshotListResult:
    """
    Paginated snapshot record page returned by repository implementations.
    """

    items: list[SnapshotRecord]
    total_items: int


class SnapshotRepository(Protocol):
    """
    Abstract persistence contract for snapshot records.
    """

    def create(self, record: SnapshotRecord) -> SnapshotRecord:
        """
        Persist a new snapshot record.
        """
        ...

    def get(self, snapshot_id: str) -> SnapshotRecord | None:
        """
        Fetch a snapshot record by id.
        """
        ...

    def list(self, query: SnapshotListQuery) -> SnapshotListResult:
        """
        List snapshot records with optional filtering and pagination.
        """
        ...

    def list_recoverable_operations(
        self,
        states: list[SnapshotState],
        limit: int,
    ) -> list[SnapshotRecord]:
        """List a bounded set of unowned or expired operations."""
        ...

    def update(self, record: SnapshotRecord) -> SnapshotRecord:
        """
        Replace the persisted contents of an existing snapshot record.
        """
        ...

    def update_if_state(
        self,
        record: SnapshotRecord,
        expected_state: SnapshotState,
    ) -> bool:
        """
        Replace a snapshot record only if its current state matches the expected state.
        """
        ...

    def delete(self, snapshot_id: str) -> None:
        """
        Delete a snapshot record by id.
        """
        ...

    @property
    def supports_distributed_leases(self) -> bool:
        """Whether operation leases coordinate independent server processes."""
        ...

    def claim_operation(
        self,
        snapshot_id: str,
        expected_state: SnapshotState,
        lease_owner: str,
        lease_duration: timedelta,
    ) -> SnapshotRecord | None:
        """Atomically claim an unowned or expired snapshot operation."""
        ...

    def renew_operation(
        self,
        snapshot_id: str,
        expected_state: SnapshotState,
        lease_owner: str,
        operation_generation: int,
        lease_duration: timedelta,
    ) -> bool:
        """Extend a live operation lease owned by the supplied generation."""
        ...

    def update_if_operation_owner(
        self,
        record: SnapshotRecord,
        expected_state: SnapshotState,
        lease_owner: str,
        operation_generation: int,
    ) -> bool:
        """Update only while the caller still owns the live operation lease."""
        ...

    def delete_if_operation_owner(
        self,
        snapshot_id: str,
        expected_state: SnapshotState,
        lease_owner: str,
        operation_generation: int,
    ) -> bool:
        """Delete only while the caller still owns the live operation lease."""
        ...

    def close(self) -> None:
        """
        Release resources owned by the repository.
        """
        ...


__all__ = [
    "SnapshotRepository",
    "SnapshotListQuery",
    "SnapshotListResult",
]

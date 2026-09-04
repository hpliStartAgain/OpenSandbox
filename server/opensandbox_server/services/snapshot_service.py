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
Snapshot service orchestration for server-managed snapshot resources.

The preferred path is to persist the snapshot record and, when supported by the
runtime, complete snapshot creation inline so the repository reaches a terminal
state within the request lifecycle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import logging
from math import ceil
import os
import socket
from threading import BoundedSemaphore, Event, Lock, Thread
from uuid import uuid4

from fastapi import HTTPException, status

from opensandbox_server.api.schema import (
    CreateSnapshotRequest,
    ListSnapshotsRequest,
    ListSnapshotsResponse,
    PaginationInfo,
    Snapshot,
    SnapshotStatus,
)
from opensandbox_server.repositories.snapshots.factory import get_snapshot_repository
from opensandbox_server.services.constants import SnapshotErrorCodes
from opensandbox_server.services.snapshot_runtime import (
    NoopSnapshotRuntime,
    SnapshotRuntime,
    SnapshotRuntimeStatus,
)
from opensandbox_server.services.snapshot_runtime_factory import create_snapshot_runtime
from opensandbox_server.services.snapshot_models import (
    SnapshotRecord,
    SnapshotRestoreConfig,
    SnapshotState,
    SnapshotStatusRecord,
)
from opensandbox_server.services.snapshot_repository import (
    SnapshotListQuery,
    SnapshotRepository,
)
from opensandbox_server.tenants.context import get_current_tenant

logger = logging.getLogger(__name__)
SNAPSHOT_RECOVERY_PAGE_SIZE = 200
SNAPSHOT_WORKER_MAX_WORKERS = 2
SNAPSHOT_OPERATION_LEASE_SECONDS = 30.0
SNAPSHOT_LEASE_RENEW_INTERVAL_SECONDS = 10.0
SNAPSHOT_RECOVERY_INTERVAL_SECONDS = 5.0


class SnapshotService(ABC):
    """
    Abstract service interface for snapshot lifecycle operations.
    """

    @abstractmethod
    def create_snapshot(self, sandbox_id: str, request: CreateSnapshotRequest) -> Snapshot:
        pass

    @abstractmethod
    def list_snapshots(self, request: ListSnapshotsRequest) -> ListSnapshotsResponse:
        pass

    @abstractmethod
    def get_snapshot(self, snapshot_id: str) -> Snapshot:
        pass

    @abstractmethod
    def delete_snapshot(self, snapshot_id: str) -> None:
        pass

    def close(self) -> None:
        """
        Release resources owned by the snapshot service.
        """


class PersistedSnapshotService(SnapshotService):
    """
    Snapshot service backed by the configured repository.
    """

    def __init__(
        self,
        snapshot_repository: SnapshotRepository,
        sandbox_service,
        snapshot_runtime: SnapshotRuntime | None = None,
        snapshot_executor=None,
        *,
        recover_unfinished_snapshots: bool = True,
        operation_owner: str | None = None,
        operation_lease_seconds: float = SNAPSHOT_OPERATION_LEASE_SECONDS,
        lease_renew_interval_seconds: float = SNAPSHOT_LEASE_RENEW_INTERVAL_SECONDS,
        recovery_interval_seconds: float = SNAPSHOT_RECOVERY_INTERVAL_SECONDS,
    ) -> None:
        if operation_lease_seconds <= 0:
            raise ValueError("operation_lease_seconds must be greater than zero")
        if not 0 < lease_renew_interval_seconds < operation_lease_seconds:
            raise ValueError(
                "lease_renew_interval_seconds must be greater than zero and less than "
                "operation_lease_seconds"
            )
        if recovery_interval_seconds <= 0:
            raise ValueError("recovery_interval_seconds must be greater than zero")

        self._snapshot_repository = snapshot_repository
        self._sandbox_service = sandbox_service
        self._snapshot_runtime = snapshot_runtime or NoopSnapshotRuntime()
        self._snapshot_executor = snapshot_executor or ThreadPoolExecutor(
            max_workers=SNAPSHOT_WORKER_MAX_WORKERS,
            thread_name_prefix="snapshot-create",
        )
        self._worker_slots = BoundedSemaphore(SNAPSHOT_WORKER_MAX_WORKERS)
        self._active_operations_lock = Lock()
        self._active_operations: set[tuple[str, int]] = set()
        self._operation_owner = operation_owner or self._default_operation_owner()
        self._operation_lease_duration = timedelta(seconds=operation_lease_seconds)
        self._lease_renew_interval_seconds = lease_renew_interval_seconds
        self._recovery_interval_seconds = recovery_interval_seconds
        self._recovery_stop = Event()
        self._recovery_thread_lock = Lock()
        self._recovery_thread: Thread | None = None
        if recover_unfinished_snapshots:
            self.recover_unfinished_snapshots()
            self._ensure_recovery_thread()

    def create_snapshot(self, sandbox_id: str, request: CreateSnapshotRequest) -> Snapshot:
        sandbox = self._sandbox_service.get_sandbox(sandbox_id)
        self._ensure_source_sandbox_running(sandbox)

        if not self._snapshot_runtime.supports_create_snapshot():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail={
                    "code": "SNAPSHOT::NOT_IMPLEMENTED",
                    "message": self._snapshot_runtime.create_snapshot_unsupported_message(),
                },
            )

        now = datetime.now(timezone.utc)
        record = SnapshotRecord(
            id=str(uuid4()),
            source_sandbox_id=sandbox_id,
            namespace=self._get_tenant_namespace(),
            name=request.name,
            restore_config=self._default_restore_config(),
            status=SnapshotStatusRecord(
                state=SnapshotState.CREATING,
                reason="snapshot_accepted",
                message="Snapshot creation accepted.",
                last_transition_at=now,
            ),
            created_at=now,
            updated_at=now,
        )
        self._snapshot_repository.create(record)
        self._try_start_create_operation(record, recovery=False)
        return self._to_snapshot_response(record)

    def list_snapshots(self, request: ListSnapshotsRequest) -> ListSnapshotsResponse:
        pagination = request.pagination or self._default_pagination()
        tenant = get_current_tenant()
        result = self._snapshot_repository.list(
            SnapshotListQuery(
                page=pagination.page,
                page_size=pagination.page_size,
                source_sandbox_id=request.filter.sandbox_id,
                name=request.filter.name,
                states=request.filter.state or [],
                namespace=tenant.namespace if tenant else None,
            )
        )

        total_pages = ceil(result.total_items / pagination.page_size) if result.total_items > 0 else 0
        return ListSnapshotsResponse(
            items=[self._to_snapshot_response(item) for item in result.items],
            pagination=PaginationInfo(
                page=pagination.page,
                pageSize=pagination.page_size,
                totalItems=result.total_items,
                totalPages=total_pages,
                hasNextPage=pagination.page < total_pages,
            ),
        )

    def get_snapshot(self, snapshot_id: str) -> Snapshot:
        record = self._snapshot_repository.get(snapshot_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "SNAPSHOT::NOT_FOUND",
                    "message": f"Snapshot {snapshot_id} not found",
                },
            )
        self._verify_tenant_access(record)
        return self._to_snapshot_response(record)

    def delete_snapshot(self, snapshot_id: str) -> None:
        record = self._snapshot_repository.get(snapshot_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "SNAPSHOT::NOT_FOUND",
                    "message": f"Snapshot {snapshot_id} not found",
                },
            )
        self._verify_tenant_access(record)

        if record.status.state == SnapshotState.CREATING:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "SNAPSHOT::INVALID_STATE",
                    "message": f"Snapshot {snapshot_id} is still being created and cannot be deleted",
                },
            )

        if record.status.state != SnapshotState.DELETING:
            record = self._mark_snapshot_deleting(record)
            if record is None:
                return

        try:
            claimed = self._claim_operation(record)
        except Exception:
            self._ensure_recovery_thread()
            raise
        if claimed is None:
            return
        self._delete_snapshot_worker(claimed, propagate=True)

    def close(self) -> None:
        """
        Stop accepting new snapshot work and wait for in-flight workers.
        """
        self._recovery_stop.set()
        if self._recovery_thread is not None:
            self._recovery_thread.join()
        self._snapshot_executor.shutdown(wait=True)

    @staticmethod
    def _default_restore_config():
        return SnapshotRestoreConfig(image=None)

    @staticmethod
    def _default_pagination():
        from opensandbox_server.api.schema import PaginationRequest

        return PaginationRequest(page=1, pageSize=20)

    @staticmethod
    def _get_tenant_namespace() -> str | None:
        tenant = get_current_tenant()
        return tenant.namespace if tenant else None

    @staticmethod
    def _verify_tenant_access(record: SnapshotRecord) -> None:
        tenant = get_current_tenant()
        if tenant is None:
            return
        if record.namespace is None or record.namespace != tenant.namespace:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "SNAPSHOT::NOT_FOUND",
                    "message": f"Snapshot {record.id} not found",
                },
            )

    def _mark_snapshot_deleting(self, record: SnapshotRecord) -> SnapshotRecord | None:
        now = datetime.now(timezone.utc)
        deleting_record = SnapshotRecord(
            id=record.id,
            source_sandbox_id=record.source_sandbox_id,
            namespace=record.namespace,
            name=record.name,
            description=record.description,
            restore_config=record.restore_config,
            status=SnapshotStatusRecord(
                state=SnapshotState.DELETING,
                reason="snapshot_delete_requested",
                message="Snapshot deletion requested.",
                last_transition_at=now,
            ),
            created_at=record.created_at,
            updated_at=now,
            operation_generation=record.operation_generation,
            operation_attempt=record.operation_attempt,
        )
        if self._snapshot_repository.update_if_state(
            deleting_record,
            record.status.state,
        ):
            return deleting_record

        current_record = self._snapshot_repository.get(record.id)
        if current_record is None:
            return None
        if current_record.status.state == SnapshotState.DELETING:
            return current_record

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "SNAPSHOT::INVALID_STATE",
                "message": f"Snapshot {record.id} changed state and cannot be deleted",
            },
        )

    def _create_snapshot_worker(
        self,
        record: SnapshotRecord,
        recovery: bool = False,
        heartbeat: tuple[Event, Thread | None] | None = None,
        release_worker_slot: bool = False,
    ) -> None:
        active_heartbeat = heartbeat or self._start_lease_heartbeat(record)
        operation_key = (record.id, record.operation_generation)
        with self._active_operations_lock:
            self._active_operations.add(operation_key)
        try:
            resume_runtime = recovery and record.operation_attempt > 0
            try:
                started = self._mark_operation_started(record)
            except Exception:
                self._ensure_recovery_thread()
                raise
            if started is None:
                logger.info(
                    "Snapshot %s lease generation %s became stale before runtime execution",
                    record.id,
                    record.operation_generation,
                )
                self._ensure_recovery_thread()
                return
            record = started
            try:
                if resume_runtime:
                    recover_snapshot = getattr(self._snapshot_runtime, "recover_snapshot", None)
                    if recover_snapshot is None:
                        runtime_status = self._snapshot_runtime.inspect_snapshot(
                            record.id,
                            image=record.restore_config.image,
                            namespace=record.namespace,
                        )
                    else:
                        runtime_status = recover_snapshot(
                            record.id,
                            record.source_sandbox_id,
                            image=record.restore_config.image,
                            namespace=record.namespace,
                        )
                else:
                    runtime_status = self._snapshot_runtime.create_snapshot(
                        record.id,
                        record.source_sandbox_id,
                        namespace=record.namespace,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "Failed to create snapshot %s from sandbox %s: %s",
                    record.id,
                    record.source_sandbox_id,
                    exc,
                )
                runtime_status = SnapshotRuntimeStatus(
                    state=SnapshotState.FAILED,
                    reason="snapshot_runtime_failed",
                    message=str(exc),
                )

            if runtime_status is None:
                runtime_status = SnapshotRuntimeStatus(
                    state=SnapshotState.FAILED,
                    reason="snapshot_runtime_missing_result",
                    message="Snapshot runtime did not return a final status.",
                )

            self._complete_snapshot(record, runtime_status)
        finally:
            with self._active_operations_lock:
                self._active_operations.discard(operation_key)
            self._stop_lease_heartbeat(active_heartbeat)
            if release_worker_slot:
                self._worker_slots.release()

    def _log_worker_failure(self, future: Future) -> None:
        try:
            future.result()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Snapshot worker exited unexpectedly: %s", exc)

    def _complete_snapshot(self, record: SnapshotRecord, runtime_status) -> None:
        if record.lease_owner is None:
            logger.warning(
                "Snapshot %s worker completed without an operation lease; skipping update",
                record.id,
            )
            return

        updated = self._build_runtime_status_record(record, runtime_status)
        if updated is None:
            self._ensure_recovery_thread()
            return

        try:
            updated_applied = self._snapshot_repository.update_if_operation_owner(
                updated,
                SnapshotState.CREATING,
                record.lease_owner,
                record.operation_generation,
            )
        except Exception:
            self._ensure_recovery_thread()
            raise
        if not updated_applied:
            logger.info(
                "Snapshot %s lease generation %s is stale; skipping terminal update",
                record.id,
                record.operation_generation,
            )
            self._ensure_recovery_thread()

    def recover_unfinished_snapshots(self) -> None:
        self._recover_creating_snapshots()
        self._recover_deleting_snapshots()

    def _recover_creating_snapshots(self) -> None:
        while self._has_available_worker_slot():
            records = self._snapshot_repository.list_recoverable_operations(
                [SnapshotState.CREATING],
                SNAPSHOT_WORKER_MAX_WORKERS,
            )
            if not records:
                return
            if not self._recover_records(records):
                self._ensure_recovery_thread()
                return
        self._ensure_recovery_thread()

    def _recover_deleting_snapshots(self) -> None:
        while True:
            records = self._snapshot_repository.list_recoverable_operations(
                [SnapshotState.DELETING],
                SNAPSHOT_RECOVERY_PAGE_SIZE,
            )
            if not records:
                return
            if not self._recover_records(records):
                self._ensure_recovery_thread()
                return

    def _recover_records(self, records: list[SnapshotRecord]) -> bool:
        all_progressed = True
        for record in records:
            try:
                if not self._recover_unfinished_snapshot(record):
                    all_progressed = False
            except Exception as exc:  # noqa: BLE001
                all_progressed = False
                logger.warning(
                    "Failed to recover unfinished snapshot %s: %s",
                    record.id,
                    exc,
                    exc_info=True,
                )
        return all_progressed

    def _has_available_worker_slot(self) -> bool:
        if not self._worker_slots.acquire(blocking=False):
            return False
        self._worker_slots.release()
        return True

    def _recover_unfinished_snapshot(self, record: SnapshotRecord) -> bool:
        if record.status.state == SnapshotState.CREATING:
            if self._is_locally_active_operation(record):
                self._ensure_recovery_thread()
                return False
            return self._try_start_create_operation(record, recovery=True)

        if record.status.state == SnapshotState.DELETING:
            try:
                claimed = self._claim_operation(record)
            except Exception:
                self._ensure_recovery_thread()
                raise
            if claimed is None:
                self._ensure_recovery_thread()
                return False
            return self._delete_snapshot_worker(claimed, propagate=False)

        return False

    def _build_runtime_status_record(
        self,
        record: SnapshotRecord,
        runtime_status,
    ) -> SnapshotRecord | None:
        now = datetime.now(timezone.utc)
        if runtime_status.state == SnapshotState.READY:
            if not runtime_status.image:
                return SnapshotRecord(
                    id=record.id,
                    source_sandbox_id=record.source_sandbox_id,
                    namespace=record.namespace,
                    name=record.name,
                    description=record.description,
                    restore_config=record.restore_config,
                    status=SnapshotStatusRecord(
                        state=SnapshotState.FAILED,
                        reason="snapshot_runtime_missing_image",
                        message="Runtime reported Ready without a snapshot image.",
                        last_transition_at=now,
                    ),
                    created_at=record.created_at,
                    updated_at=now,
                    operation_generation=record.operation_generation,
                    operation_attempt=record.operation_attempt,
                )

            return SnapshotRecord(
                id=record.id,
                source_sandbox_id=record.source_sandbox_id,
                namespace=record.namespace,
                name=record.name,
                description=record.description,
                restore_config=SnapshotRestoreConfig(image=runtime_status.image),
                status=SnapshotStatusRecord(
                    state=SnapshotState.READY,
                    reason=runtime_status.reason,
                    message=runtime_status.message,
                    last_transition_at=now,
                ),
                created_at=record.created_at,
                updated_at=now,
                operation_generation=record.operation_generation,
                operation_attempt=record.operation_attempt,
            )

        if runtime_status.state == SnapshotState.FAILED:
            return SnapshotRecord(
                id=record.id,
                source_sandbox_id=record.source_sandbox_id,
                namespace=record.namespace,
                name=record.name,
                description=record.description,
                restore_config=record.restore_config,
                status=SnapshotStatusRecord(
                    state=SnapshotState.FAILED,
                    reason=runtime_status.reason,
                    message=runtime_status.message,
                    last_transition_at=now,
                ),
                created_at=record.created_at,
                updated_at=now,
                operation_generation=record.operation_generation,
                operation_attempt=record.operation_attempt,
            )

        return None

    def _claim_operation(self, record: SnapshotRecord) -> SnapshotRecord | None:
        return self._snapshot_repository.claim_operation(
            record.id,
            record.status.state,
            self._operation_owner,
            self._operation_lease_duration,
        )

    def _mark_operation_started(self, record: SnapshotRecord) -> SnapshotRecord | None:
        if record.lease_owner is None:
            return None
        return self._snapshot_repository.mark_operation_started(
            record.id,
            record.status.state,
            record.lease_owner,
            record.operation_generation,
        )

    def _is_locally_active_operation(self, record: SnapshotRecord) -> bool:
        if record.lease_owner != self._operation_owner:
            return False
        with self._active_operations_lock:
            return (record.id, record.operation_generation) in self._active_operations

    def _try_start_create_operation(
        self,
        record: SnapshotRecord,
        *,
        recovery: bool,
    ) -> bool:
        if not self._worker_slots.acquire(blocking=False):
            self._ensure_recovery_thread()
            return False

        claimed = None
        try:
            claimed = self._claim_operation(record)
            if claimed is None:
                self._worker_slots.release()
                self._ensure_recovery_thread()
                return False
            self._submit_claimed_create_worker(claimed, recovery=recovery)
        except BaseException as exc:
            if claimed is None:
                self._worker_slots.release()
            if isinstance(exc, Exception):
                self._ensure_recovery_thread()
            raise
        return True

    def _submit_claimed_create_worker(self, record: SnapshotRecord, *, recovery: bool) -> None:
        heartbeat: tuple[Event, Thread | None] | None = None
        try:
            heartbeat = self._start_lease_heartbeat(record)
            future = self._snapshot_executor.submit(
                self._create_snapshot_worker,
                record,
                recovery,
                heartbeat,
                True,
            )
        except BaseException:
            if heartbeat is not None:
                self._stop_lease_heartbeat(heartbeat)
            self._worker_slots.release()
            raise
        future.add_done_callback(self._log_worker_failure)

    def _delete_snapshot_worker(self, record: SnapshotRecord, *, propagate: bool) -> bool:
        heartbeat = self._start_lease_heartbeat(record)
        try:
            started = self._mark_operation_started(record)
            if started is None:
                logger.info(
                    "Snapshot %s lease generation %s became stale before runtime deletion",
                    record.id,
                    record.operation_generation,
                )
                self._ensure_recovery_thread()
                return False
            record = started
            self._snapshot_runtime.delete_snapshot(
                record.id,
                image=record.restore_config.image,
                namespace=record.namespace,
            )
            deleted = self._snapshot_repository.delete_if_operation_owner(
                record.id,
                SnapshotState.DELETING,
                record.lease_owner or "",
                record.operation_generation,
            )
            if not deleted:
                logger.info(
                    "Snapshot %s lease generation %s is stale; retaining metadata for recovery",
                    record.id,
                    record.operation_generation,
                )
                self._ensure_recovery_thread()
            return deleted
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to delete snapshot %s while holding generation %s: %s",
                record.id,
                record.operation_generation,
                exc,
                exc_info=True,
            )
            self._ensure_recovery_thread()
            if propagate:
                raise
            return False
        finally:
            self._stop_lease_heartbeat(heartbeat)

    def _start_lease_heartbeat(self, record: SnapshotRecord) -> tuple[Event, Thread | None]:
        stop = Event()
        if record.lease_owner is None:
            return stop, None

        def renew() -> None:
            while not stop.wait(self._lease_renew_interval_seconds):
                try:
                    renewed = self._snapshot_repository.renew_operation(
                        record.id,
                        record.status.state,
                        record.lease_owner or "",
                        record.operation_generation,
                        self._operation_lease_duration,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to renew snapshot %s lease generation %s: %s",
                        record.id,
                        record.operation_generation,
                        exc,
                    )
                    continue
                if not renewed:
                    logger.info(
                        "Snapshot %s lease generation %s is no longer owned by this worker",
                        record.id,
                        record.operation_generation,
                    )
                    return

        thread = Thread(
            target=renew,
            name=f"snapshot-lease-{record.id[:8]}",
            daemon=True,
        )
        thread.start()
        return stop, thread

    def _stop_lease_heartbeat(self, heartbeat: tuple[Event, Thread | None]) -> None:
        stop, thread = heartbeat
        stop.set()
        if thread is not None:
            thread.join(timeout=self._lease_renew_interval_seconds + 1)

    def _recovery_loop(self) -> None:
        while not self._recovery_stop.wait(self._recovery_interval_seconds):
            try:
                self.recover_unfinished_snapshots()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Snapshot recovery scan failed: %s", exc, exc_info=True)

    def _ensure_recovery_thread(self) -> None:
        if self._recovery_stop.is_set():
            return
        with self._recovery_thread_lock:
            if self._recovery_thread is not None and self._recovery_thread.is_alive():
                return
            self._recovery_thread = Thread(
                target=self._recovery_loop,
                name="snapshot-recovery",
                daemon=True,
            )
            self._recovery_thread.start()

    @staticmethod
    def _default_operation_owner() -> str:
        return f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"

    @staticmethod
    def _ensure_source_sandbox_running(sandbox) -> None:
        state = PersistedSnapshotService._sandbox_state(sandbox)
        if state == "Running":
            return

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": SnapshotErrorCodes.INVALID_SOURCE_STATE,
                "message": "Snapshot can only be created from a Running sandbox.",
            },
        )

    @staticmethod
    def _sandbox_state(sandbox) -> str | None:
        if isinstance(sandbox, dict):
            status_value = sandbox.get("status")
            if isinstance(status_value, dict):
                return status_value.get("state")
            return getattr(status_value, "state", None)

        status_value = getattr(sandbox, "status", None)
        if isinstance(status_value, dict):
            return status_value.get("state")
        return getattr(status_value, "state", None)

    @staticmethod
    def _to_snapshot_response(record: SnapshotRecord) -> Snapshot:
        return Snapshot(
            id=record.id,
            sandboxId=record.source_sandbox_id,
            name=record.name,
            status=SnapshotStatus(
                state=record.status.state.value,
                reason=record.status.reason,
                message=record.status.message,
                lastTransitionAt=record.status.last_transition_at,
            ),
            createdAt=record.created_at,
        )


def create_snapshot_service(sandbox_service) -> SnapshotService:
    """
    Build the default persisted snapshot service.
    """
    snapshot_runtime: SnapshotRuntime = create_snapshot_runtime(
        docker_client=getattr(sandbox_service, "docker_client", None),
    )

    return PersistedSnapshotService(
        snapshot_repository=get_snapshot_repository(),
        sandbox_service=sandbox_service,
        snapshot_runtime=snapshot_runtime,
    )


__all__ = [
    "SnapshotService",
    "PersistedSnapshotService",
    "create_snapshot_service",
    "SNAPSHOT_WORKER_MAX_WORKERS",
]

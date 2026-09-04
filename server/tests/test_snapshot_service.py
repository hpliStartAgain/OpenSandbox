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

from concurrent.futures import Future
from datetime import timedelta
from threading import Event, Lock
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from opensandbox_server.api.schema import CreateSnapshotRequest, ListSnapshotsRequest, SnapshotFilter
from opensandbox_server.repositories.snapshots.sqlite import SQLiteSnapshotRepository
from opensandbox_server.services.snapshot_models import (
    SnapshotRecord,
    SnapshotRestoreConfig,
    SnapshotState,
    SnapshotStatusRecord,
)
from opensandbox_server.services.snapshot_runtime import NoopSnapshotRuntime, SnapshotRuntimeStatus
from opensandbox_server.services.snapshot_repository import SnapshotListQuery
from opensandbox_server.services.snapshot_service import PersistedSnapshotService


class StubSandboxService:
    @staticmethod
    def get_sandbox(sandbox_id: str):
        if sandbox_id == "missing":
            raise HTTPException(
                status_code=404,
                detail={"code": "SANDBOX::NOT_FOUND", "message": f"Sandbox {sandbox_id} not found"},
        )
        return {
            "id": sandbox_id,
            "status": {
                "state": "Running",
            },
        }


class ImmediateExecutor:
    def __init__(self) -> None:
        self.shutdown_called = False

    def submit(self, fn, *args, **kwargs) -> Future:
        future = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001
            future.set_exception(exc)
        return future

    def shutdown(self, wait: bool = True) -> None:
        self.shutdown_called = True


class FailOnceSubmitExecutor(ImmediateExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.submit_attempts = 0

    def submit(self, fn, *args, **kwargs) -> Future:
        self.submit_attempts += 1
        if self.submit_attempts == 1:
            raise RuntimeError("simulated executor submission failure")
        return super().submit(fn, *args, **kwargs)


class CapturingExecutor:
    def __init__(self) -> None:
        self.submitted: list[tuple[object, tuple, dict]] = []
        self.shutdown_called = False
        self.shutdown_wait = None

    def submit(self, fn, *args, **kwargs) -> Future:
        self.submitted.append((fn, args, kwargs))
        return Future()

    def shutdown(self, wait: bool = True) -> None:
        self.shutdown_called = True
        self.shutdown_wait = wait


class StubSnapshotRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.delete_calls: list[tuple[str, str | None]] = []
        self.inspect_status_by_snapshot_id: dict[str, SnapshotRuntimeStatus] = {}

    def supports_create_snapshot(self) -> bool:
        return True

    def create_snapshot_unsupported_message(self) -> str:
        return ""

    def create_snapshot(self, snapshot_id: str, sandbox_id: str, *, namespace: str | None = None):
        self.calls.append((snapshot_id, sandbox_id))
        return None

    def get_snapshot_status(self, snapshot_id: str):
        return None

    def delete_snapshot(self, snapshot_id: str, image: str | None = None, *, namespace: str | None = None) -> None:
        self.delete_calls.append((snapshot_id, image))

    def inspect_snapshot(self, snapshot_id: str, image: str | None = None, *, namespace: str | None = None) -> SnapshotRuntimeStatus:
        return self.inspect_status_by_snapshot_id.get(
            snapshot_id,
            SnapshotRuntimeStatus(
                state=SnapshotState.FAILED,
                reason="snapshot_recovery_missing_image",
                message="Snapshot creation was interrupted and no snapshot image was found.",
            ),
        )


class BlockingRecoveryRuntime(StubSnapshotRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.release = Event()
        self.two_started = Event()
        self.three_started = Event()
        self._started_ids: list[str] = []
        self._started_lock = Lock()

    def recover_snapshot(
        self,
        snapshot_id: str,
        sandbox_id: str,
        image: str | None = None,
        *,
        namespace: str | None = None,
    ) -> SnapshotRuntimeStatus:
        with self._started_lock:
            self._started_ids.append(snapshot_id)
            if len(self._started_ids) >= 2:
                self.two_started.set()
            if len(self._started_ids) >= 3:
                self.three_started.set()
        if not self.release.wait(timeout=2):
            raise TimeoutError("test did not release snapshot recovery")
        return SnapshotRuntimeStatus(
            state=SnapshotState.READY,
            image=f"registry/snapshots:{snapshot_id}",
            reason="snapshot_runtime_ready",
        )


class FailOnceDeleteRuntime(StubSnapshotRuntime):
    def delete_snapshot(
        self,
        snapshot_id: str,
        image: str | None = None,
        *,
        namespace: str | None = None,
    ) -> None:
        self.delete_calls.append((snapshot_id, image))
        if len(self.delete_calls) == 1:
            raise RuntimeError("transient delete failure")


class CreatingOnceRuntime(StubSnapshotRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.recover_calls: list[str] = []

    def create_snapshot(
        self,
        snapshot_id: str,
        sandbox_id: str,
        *,
        namespace: str | None = None,
    ) -> SnapshotRuntimeStatus:
        self.calls.append((snapshot_id, sandbox_id))
        return SnapshotRuntimeStatus(
            state=SnapshotState.CREATING,
            reason="snapshot_runtime_inspect_failed",
            message="Kubernetes API observation timed out.",
        )

    def recover_snapshot(
        self,
        snapshot_id: str,
        sandbox_id: str,
        image: str | None = None,
        *,
        namespace: str | None = None,
    ) -> SnapshotRuntimeStatus:
        self.recover_calls.append(snapshot_id)
        return SnapshotRuntimeStatus(
            state=SnapshotState.READY,
            image=f"registry/snapshots:{snapshot_id}",
            reason="snapshot_runtime_ready",
        )


class ReadyCreateRuntime(StubSnapshotRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.recover_calls: list[str] = []

    def create_snapshot(
        self,
        snapshot_id: str,
        sandbox_id: str,
        *,
        namespace: str | None = None,
    ) -> SnapshotRuntimeStatus:
        self.calls.append((snapshot_id, sandbox_id))
        return SnapshotRuntimeStatus(
            state=SnapshotState.READY,
            image=f"registry/snapshots:{snapshot_id}",
            reason="snapshot_runtime_ready",
        )

    def recover_snapshot(
        self,
        snapshot_id: str,
        sandbox_id: str,
        image: str | None = None,
        *,
        namespace: str | None = None,
    ) -> SnapshotRuntimeStatus:
        self.recover_calls.append(snapshot_id)
        return SnapshotRuntimeStatus(
            state=SnapshotState.READY,
            image=f"registry/snapshots:{snapshot_id}",
            reason="snapshot_runtime_ready",
        )


class DistributedSQLiteSnapshotRepository(SQLiteSnapshotRepository):
    @property
    def supports_distributed_leases(self) -> bool:
        return True


def _snapshot_record(
    snapshot_id: str,
    state: SnapshotState,
    *,
    image: str | None = None,
) -> SnapshotRecord:
    return SnapshotRecord(
        id=snapshot_id,
        source_sandbox_id="sbx-001",
        restore_config=SnapshotRestoreConfig(image=image),
        status=SnapshotStatusRecord(state=state),
    )


def test_snapshot_service_persists_create_and_get(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint-before-import"))
    fetched = service.get_snapshot(created.id)

    assert created.status.state == "Creating"
    assert created.status.reason == "snapshot_accepted"
    assert fetched.id == created.id
    assert fetched.sandbox_id == "sbx-001"
    assert runtime.calls == [(created.id, "sbx-001")]


def test_snapshot_service_rejects_create_when_source_sandbox_not_running(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    sandbox_service = SimpleNamespace(
        get_sandbox=lambda sandbox_id: SimpleNamespace(
            id=sandbox_id,
            status=SimpleNamespace(state="Paused"),
        )
    )
    service = PersistedSnapshotService(
        repo,
        sandbox_service,
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    with pytest.raises(HTTPException) as exc_info:
        service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["code"] == "SNAPSHOT::INVALID_SOURCE_STATE"
    assert runtime.calls == []


def test_snapshot_service_rejects_create_when_source_sandbox_state_missing(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    sandbox_service = SimpleNamespace(
        get_sandbox=lambda sandbox_id: SimpleNamespace(id=sandbox_id)
    )
    service = PersistedSnapshotService(
        repo,
        sandbox_service,
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    with pytest.raises(HTTPException) as exc_info:
        service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["code"] == "SNAPSHOT::INVALID_SOURCE_STATE"
    assert runtime.calls == []


def test_snapshot_service_marks_snapshot_ready_from_worker(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    ready_status = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="opensandbox-snapshots:snap-ready",
        reason="snapshot_runtime_ready",
        message="Docker snapshot image created successfully.",
    )

    def create_snapshot(snapshot_id: str, sandbox_id: str, **kwargs):
        runtime.calls.append((snapshot_id, sandbox_id))
        return ready_status

    runtime.create_snapshot = create_snapshot

    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint-before-import"))
    stored = repo.get(created.id)

    assert created.status.state == "Creating"
    assert created.status.reason == "snapshot_accepted"
    assert stored is not None
    assert stored.status.state == SnapshotState.READY
    assert stored.restore_config.image == "opensandbox-snapshots:snap-ready"


def test_snapshot_service_marks_snapshot_failed_from_worker(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    failed_status = SnapshotRuntimeStatus(
        state=SnapshotState.FAILED,
        reason="snapshot_runtime_timeout",
        message="Docker snapshot creation timed out after 45 seconds.",
    )

    def create_snapshot(snapshot_id: str, sandbox_id: str, **kwargs):
        runtime.calls.append((snapshot_id, sandbox_id))
        return failed_status

    runtime.create_snapshot = create_snapshot

    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint-before-import"))
    stored = repo.get(created.id)

    assert created.status.state == "Creating"
    assert created.status.reason == "snapshot_accepted"
    assert stored is not None
    assert stored.status.state == SnapshotState.FAILED
    assert stored.status.reason == "snapshot_runtime_timeout"


def test_snapshot_service_marks_snapshot_failed_when_worker_returns_none(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint-before-import"))
    stored = repo.get(created.id)

    assert created.status.state == "Creating"
    assert stored is not None
    assert stored.status.state == SnapshotState.FAILED
    assert stored.status.reason == "snapshot_runtime_missing_result"


def test_sqlite_nonterminal_create_is_recovered_after_lease_expiry(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = CreatingOnceRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
        operation_lease_seconds=0.1,
        lease_renew_interval_seconds=0.02,
        recovery_interval_seconds=0.01,
    )

    try:
        created = service.create_snapshot(
            "sbx-001",
            CreateSnapshotRequest(name="eventually-observed"),
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = repo.get(created.id)
            if stored is not None and stored.status.state == SnapshotState.READY:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite nonterminal creation was not recovered after lease expiry")

        assert runtime.calls == [(created.id, "sbx-001")]
        assert runtime.recover_calls == [created.id]
    finally:
        service.close()


def test_sqlite_rejected_terminal_update_is_recovered(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = ReadyCreateRuntime()
    original_update = repo.update_if_operation_owner
    update_attempts = 0

    def reject_first_terminal_update(*args, **kwargs) -> bool:
        nonlocal update_attempts
        update_attempts += 1
        if update_attempts == 1:
            with repo._connect() as conn:
                conn.execute(
                    "UPDATE snapshots SET lease_expires_at = ? WHERE id = ?",
                    ("1970-01-01T00:00:00+00:00", args[0].id),
                )
            return False
        return original_update(*args, **kwargs)

    repo.update_if_operation_owner = reject_first_terminal_update
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
        recovery_interval_seconds=0.01,
    )

    try:
        created = service.create_snapshot(
            "sbx-001",
            CreateSnapshotRequest(name="fenced-terminal-retry"),
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = repo.get(created.id)
            if stored is not None and stored.status.state == SnapshotState.READY:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite rejected terminal update was not recovered")

        assert update_attempts == 2
        assert runtime.recover_calls == [created.id]
    finally:
        service.close()


def test_sqlite_terminal_update_exception_is_recovered(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = ReadyCreateRuntime()
    original_update = repo.update_if_operation_owner
    update_attempts = 0

    def fail_first_terminal_update(*args, **kwargs) -> bool:
        nonlocal update_attempts
        update_attempts += 1
        if update_attempts == 1:
            with repo._connect() as conn:
                conn.execute(
                    "UPDATE snapshots SET lease_expires_at = ? WHERE id = ?",
                    ("1970-01-01T00:00:00+00:00", args[0].id),
                )
            raise RuntimeError("simulated SQLite writer contention")
        return original_update(*args, **kwargs)

    repo.update_if_operation_owner = fail_first_terminal_update
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
        recovery_interval_seconds=0.01,
    )

    try:
        created = service.create_snapshot(
            "sbx-001",
            CreateSnapshotRequest(name="terminal-write-exception"),
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = repo.get(created.id)
            if stored is not None and stored.status.state == SnapshotState.READY:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite terminal update exception was not recovered")

        assert update_attempts == 2
        assert runtime.recover_calls == [created.id]
    finally:
        service.close()


def test_sqlite_claim_exception_after_create_is_recovered(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = ReadyCreateRuntime()
    original_claim = repo.claim_operation
    claim_attempts = 0

    def fail_first_claim(*args, **kwargs):
        nonlocal claim_attempts
        claim_attempts += 1
        if claim_attempts == 1:
            raise RuntimeError("simulated SQLite claim contention")
        return original_claim(*args, **kwargs)

    repo.claim_operation = fail_first_claim
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
        recovery_interval_seconds=0.01,
    )

    try:
        with pytest.raises(RuntimeError, match="simulated SQLite claim contention"):
            service.create_snapshot(
                "sbx-001",
                CreateSnapshotRequest(name="claim-exception"),
            )

        deadline = time.monotonic() + 2
        recovered = None
        while time.monotonic() < deadline:
            records = repo.list(SnapshotListQuery(page=1, page_size=10)).items
            if records and records[0].status.state == SnapshotState.READY:
                recovered = records[0]
                break
            time.sleep(0.01)
        if recovered is None:
            pytest.fail("SQLite claim exception left an orphaned Creating row")

        assert claim_attempts == 2
        assert runtime.recover_calls == [recovered.id]
    finally:
        service.close()


def test_sqlite_submit_exception_after_claim_is_recovered(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = ReadyCreateRuntime()
    executor = FailOnceSubmitExecutor()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=executor,
        operation_lease_seconds=0.1,
        lease_renew_interval_seconds=0.02,
        recovery_interval_seconds=0.01,
    )

    try:
        with pytest.raises(RuntimeError, match="simulated executor submission failure"):
            service.create_snapshot(
                "sbx-001",
                CreateSnapshotRequest(name="submit-exception"),
            )

        deadline = time.monotonic() + 2
        recovered = None
        while time.monotonic() < deadline:
            records = repo.list(SnapshotListQuery(page=1, page_size=10)).items
            if records and records[0].status.state == SnapshotState.READY:
                recovered = records[0]
                break
            time.sleep(0.01)
        if recovered is None:
            pytest.fail("SQLite submit exception left an orphaned Creating row")

        assert executor.submit_attempts == 2
        assert runtime.recover_calls == [recovered.id]
    finally:
        service.close()


def test_recover_unfinished_snapshot_claims_and_reschedules_creating_runtime_status(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    record = _snapshot_record("snap-in-progress", SnapshotState.CREATING)
    repo.create(record)
    runtime = StubSnapshotRuntime()
    runtime.inspect_status_by_snapshot_id[record.id] = SnapshotRuntimeStatus(
        state=SnapshotState.CREATING,
        reason="snapshot_runtime_in_progress",
        message="Snapshot is still being committed.",
    )
    executor = CapturingExecutor()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=executor,
        recover_unfinished_snapshots=False,
    )

    progressed = service._recover_unfinished_snapshot(record)

    stored = repo.get(record.id)
    assert progressed is True
    assert stored is not None
    assert stored.status.state == SnapshotState.CREATING
    assert stored.lease_owner is not None
    assert stored.operation_generation == 1
    assert len(executor.submitted) == 1

    heartbeat = executor.submitted[0][1][2]
    service._stop_lease_heartbeat(heartbeat)


def test_two_services_share_one_unfinished_operation_owner(tmp_path) -> None:
    db_path = tmp_path / "snapshots.db"
    first_repo = SQLiteSnapshotRepository(db_path)
    second_repo = SQLiteSnapshotRepository(db_path)
    record = _snapshot_record("snap-shared", SnapshotState.CREATING)
    first_repo.create(record)
    first_executor = CapturingExecutor()
    second_executor = CapturingExecutor()
    first_service = PersistedSnapshotService(
        first_repo,
        StubSandboxService(),
        snapshot_runtime=StubSnapshotRuntime(),
        snapshot_executor=first_executor,
        recover_unfinished_snapshots=False,
        operation_owner="server-a",
    )
    second_service = PersistedSnapshotService(
        second_repo,
        StubSandboxService(),
        snapshot_runtime=StubSnapshotRuntime(),
        snapshot_executor=second_executor,
        recover_unfinished_snapshots=False,
        operation_owner="server-b",
    )

    assert first_service._recover_unfinished_snapshot(record) is True
    current = second_repo.get(record.id)
    assert current is not None
    assert second_service._recover_unfinished_snapshot(current) is False
    assert len(first_executor.submitted) == 1
    assert second_executor.submitted == []

    stored = first_repo.get(record.id)
    assert stored is not None
    assert stored.lease_owner == "server-a"
    assert stored.operation_generation == 1
    heartbeat = first_executor.submitted[0][1][2]
    first_service._stop_lease_heartbeat(heartbeat)


def test_recovery_claims_only_available_worker_slots(tmp_path) -> None:
    repo = DistributedSQLiteSnapshotRepository(tmp_path / "snapshots.db")
    records = [
        _snapshot_record(f"snap-queued-{index}", SnapshotState.CREATING)
        for index in range(3)
    ]
    for record in records:
        repo.create(record)
    runtime = BlockingRecoveryRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        recover_unfinished_snapshots=False,
        recovery_interval_seconds=60,
    )

    try:
        service.recover_unfinished_snapshots()
        assert runtime.two_started.wait(timeout=2)
        stored = [repo.get(record.id) for record in records]
        assert sum(item is not None and item.lease_owner is not None for item in stored) == 2
        assert sum(item is not None and item.lease_owner is None for item in stored) == 1

        service.recover_unfinished_snapshots()
        stored = [repo.get(record.id) for record in records]
        assert sum(item is not None and item.lease_owner is not None for item in stored) == 2
        assert runtime.three_started.is_set() is False

        runtime.release.set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if sum(
                item is not None and item.status.state == SnapshotState.READY
                for item in (repo.get(record.id) for record in records)
            ) >= 2:
                break
            time.sleep(0.01)
        else:
            pytest.fail("initial recovery workers did not complete")

        service.recover_unfinished_snapshots()
        assert runtime.three_started.wait(timeout=2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            final = [repo.get(record.id) for record in records]
            if all(item is not None and item.status.state == SnapshotState.READY for item in final):
                break
            time.sleep(0.01)
        else:
            pytest.fail("queued recovery did not complete after a worker slot became free")
    finally:
        runtime.release.set()
        service.close()


def test_stale_service_completion_is_rejected_after_takeover(tmp_path) -> None:
    db_path = tmp_path / "snapshots.db"
    first_repo = SQLiteSnapshotRepository(db_path)
    second_repo = SQLiteSnapshotRepository(db_path)
    record = _snapshot_record("snap-stale", SnapshotState.CREATING)
    first_repo.create(record)
    first_claim = first_repo.claim_operation(
        record.id,
        SnapshotState.CREATING,
        "server-a",
        timedelta(seconds=30),
    )
    assert first_claim is not None
    with first_repo._connect() as conn:
        conn.execute(
            "UPDATE snapshots SET lease_expires_at = ? WHERE id = ?",
            ("1970-01-01T00:00:00+00:00", record.id),
        )
    second_claim = second_repo.claim_operation(
        record.id,
        SnapshotState.CREATING,
        "server-b",
        timedelta(seconds=30),
    )
    assert second_claim is not None
    first_service = PersistedSnapshotService(
        first_repo,
        StubSandboxService(),
        recover_unfinished_snapshots=False,
        operation_owner="server-a",
    )
    second_service = PersistedSnapshotService(
        second_repo,
        StubSandboxService(),
        recover_unfinished_snapshots=False,
        operation_owner="server-b",
    )
    ready_status = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="registry/sandbox:snap-stale",
        reason="snapshot_runtime_ready",
    )

    first_service._complete_snapshot(first_claim, ready_status)
    after_stale = second_repo.get(record.id)
    assert after_stale is not None
    assert after_stale.status.state == SnapshotState.CREATING
    assert after_stale.lease_owner == "server-b"

    second_service._complete_snapshot(second_claim, ready_status)
    completed = first_repo.get(record.id)
    assert completed is not None
    assert completed.status.state == SnapshotState.READY
    assert completed.restore_config.image == "registry/sandbox:snap-stale"


def test_snapshot_service_lists_and_deletes_records(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    first = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="first"))
    second = service.create_snapshot("sbx-002", CreateSnapshotRequest(name="second"))

    page = service.list_snapshots(
        ListSnapshotsRequest(
            filter=SnapshotFilter(sandboxId="sbx-001"),
        )
    )

    assert page.pagination.total_items == 1
    assert [item.id for item in page.items] == [first.id]

    named_page = service.list_snapshots(
        ListSnapshotsRequest(filter=SnapshotFilter(name="second"))
    )
    assert named_page.pagination.total_items == 1
    assert [item.id for item in named_page.items] == [second.id]

    second_record = repo.get(second.id)
    assert second_record is not None
    second_record.status = SnapshotStatusRecord(state=SnapshotState.FAILED)
    repo.update(second_record)

    service.delete_snapshot(second.id)
    assert runtime.delete_calls == [(second.id, None)]
    with pytest.raises(HTTPException) as exc_info:
        service.get_snapshot(second.id)
    assert exc_info.value.status_code == 404


def test_snapshot_service_rejects_delete_while_creating(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    executor = CapturingExecutor()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=executor,
    )

    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))
    with pytest.raises(HTTPException) as exc_info:
        service.delete_snapshot(created.id)

    stored = repo.get(created.id)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["code"] == "SNAPSHOT::INVALID_STATE"
    assert stored is not None
    assert stored.status.state == SnapshotState.CREATING
    assert runtime.delete_calls == []
    assert len(executor.submitted) == 1


def test_snapshot_service_deletes_runtime_artifact_before_metadata(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    ready_status = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="opensandbox-snapshots:snap-ready",
        reason="snapshot_runtime_ready",
        message="Docker snapshot image created successfully.",
    )

    def create_snapshot(snapshot_id: str, sandbox_id: str, **kwargs):
        runtime.calls.append((snapshot_id, sandbox_id))
        return ready_status

    def delete_snapshot(snapshot_id: str, image: str | None = None, **kwargs) -> None:
        stored = repo.get(snapshot_id)
        assert stored is not None
        assert stored.status.state == SnapshotState.DELETING
        runtime.delete_calls.append((snapshot_id, image))

    runtime.create_snapshot = create_snapshot
    runtime.delete_snapshot = delete_snapshot
    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))

    service.delete_snapshot(created.id)

    assert runtime.delete_calls == [(created.id, "opensandbox-snapshots:snap-ready")]
    assert repo.get(created.id) is None


def test_snapshot_service_propagates_snapshot_delete_conflict(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
    )

    record = _snapshot_record(
        "snap-in-use",
        SnapshotState.READY,
        image="opensandbox-snapshots:snap-in-use",
    )
    repo.create(record)

    def delete_snapshot(snapshot_id: str, image: str | None = None, **kwargs) -> None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SNAPSHOT::DELETE_CONFLICT",
                "message": "snapshot image cannot be deleted due to a conflict",
            },
        )

    runtime.delete_snapshot = delete_snapshot

    with pytest.raises(HTTPException) as exc_info:
        service.delete_snapshot("snap-in-use")

    stored = repo.get("snap-in-use")
    assert exc_info.value.status_code == 409
    assert stored is not None
    assert stored.status.state == SnapshotState.DELETING


def test_snapshot_service_recovers_delete_after_runtime_cleanup_succeeds(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    record = _snapshot_record(
        "snap-delete-crash",
        SnapshotState.READY,
        image="opensandbox-snapshots:snap-delete-crash",
    )
    repo.create(record)

    original_delete_if_owner = repo.delete_if_operation_owner

    def crash_delete(*args, **kwargs) -> bool:
        raise RuntimeError("simulated metadata delete crash")

    repo.delete_if_operation_owner = crash_delete
    with pytest.raises(RuntimeError, match="simulated metadata delete crash"):
        service.delete_snapshot("snap-delete-crash")

    stored = repo.get("snap-delete-crash")
    assert stored is not None
    assert stored.status.state == SnapshotState.DELETING
    assert runtime.delete_calls == [("snap-delete-crash", "opensandbox-snapshots:snap-delete-crash")]

    repo.delete_if_operation_owner = original_delete_if_owner
    before_expiry_runtime = StubSnapshotRuntime()
    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=before_expiry_runtime,
    )
    assert before_expiry_runtime.delete_calls == []

    with repo._connect() as conn:
        conn.execute(
            "UPDATE snapshots SET lease_expires_at = ? WHERE id = ?",
            ("1970-01-01T00:00:00+00:00", "snap-delete-crash"),
        )
    recovery_runtime = StubSnapshotRuntime()
    PersistedSnapshotService(repo, StubSandboxService(), snapshot_runtime=recovery_runtime)

    assert recovery_runtime.delete_calls == [("snap-delete-crash", "opensandbox-snapshots:snap-delete-crash")]
    assert repo.get("snap-delete-crash") is None


def test_sqlite_failed_delete_schedules_recovery_after_lease_expiry(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    record = _snapshot_record(
        "snap-delete-retry",
        SnapshotState.READY,
        image="opensandbox-snapshots:snap-delete-retry",
    )
    repo.create(record)
    runtime = FailOnceDeleteRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        operation_lease_seconds=0.1,
        lease_renew_interval_seconds=0.02,
        recovery_interval_seconds=0.01,
    )

    try:
        with pytest.raises(RuntimeError, match="transient delete failure"):
            service.delete_snapshot(record.id)

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if repo.get(record.id) is None:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite deletion was not retried after its lease expired")

        assert runtime.delete_calls == [
            (record.id, "opensandbox-snapshots:snap-delete-retry"),
            (record.id, "opensandbox-snapshots:snap-delete-retry"),
        ]
    finally:
        service.close()


def test_sqlite_failed_delete_claim_schedules_recovery(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    record = _snapshot_record(
        "snap-delete-claim-retry",
        SnapshotState.READY,
        image="opensandbox-snapshots:snap-delete-claim-retry",
    )
    repo.create(record)
    runtime = StubSnapshotRuntime()
    original_claim = repo.claim_operation
    claim_attempts = 0

    def fail_first_claim(*args, **kwargs):
        nonlocal claim_attempts
        claim_attempts += 1
        if claim_attempts == 1:
            raise RuntimeError("transient claim failure")
        return original_claim(*args, **kwargs)

    repo.claim_operation = fail_first_claim
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        recovery_interval_seconds=0.01,
    )

    try:
        with pytest.raises(RuntimeError, match="transient claim failure"):
            service.delete_snapshot(record.id)

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if repo.get(record.id) is None:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite deletion was not recovered after its initial claim failed")

        assert claim_attempts == 2
        assert runtime.delete_calls == [
            (record.id, "opensandbox-snapshots:snap-delete-claim-retry"),
        ]
    finally:
        service.close()


def test_sqlite_rejected_metadata_delete_is_recovered(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    record = _snapshot_record(
        "snap-delete-fenced",
        SnapshotState.READY,
        image="opensandbox-snapshots:snap-delete-fenced",
    )
    repo.create(record)
    runtime = StubSnapshotRuntime()
    original_delete = repo.delete_if_operation_owner
    delete_attempts = 0

    def reject_first_metadata_delete(*args, **kwargs) -> bool:
        nonlocal delete_attempts
        delete_attempts += 1
        if delete_attempts == 1:
            with repo._connect() as conn:
                conn.execute(
                    "UPDATE snapshots SET lease_expires_at = ? WHERE id = ?",
                    ("1970-01-01T00:00:00+00:00", args[0]),
                )
            return False
        return original_delete(*args, **kwargs)

    repo.delete_if_operation_owner = reject_first_metadata_delete
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        recovery_interval_seconds=0.01,
    )

    try:
        service.delete_snapshot(record.id)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if repo.get(record.id) is None:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite rejected metadata deletion was not recovered")

        assert delete_attempts == 2
        assert runtime.delete_calls == [
            (record.id, "opensandbox-snapshots:snap-delete-fenced"),
            (record.id, "opensandbox-snapshots:snap-delete-fenced"),
        ]
    finally:
        service.close()


def test_snapshot_service_stale_worker_does_not_cleanup_runtime_artifact(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=CapturingExecutor(),
    )

    ready_status = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="opensandbox-snapshots:snap-ready",
        reason="snapshot_runtime_ready",
        message="Docker snapshot image created successfully.",
    )

    def create_snapshot(snapshot_id: str, sandbox_id: str, **kwargs):
        runtime.calls.append((snapshot_id, sandbox_id))
        return ready_status

    runtime.create_snapshot = create_snapshot
    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))
    repo.delete(created.id)

    service._create_snapshot_worker(_snapshot_record(created.id, SnapshotState.CREATING))

    assert runtime.delete_calls == []
    assert repo.get(created.id) is None


def test_snapshot_service_worker_does_not_overwrite_transitioned_snapshot(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    runtime = StubSnapshotRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=CapturingExecutor(),
    )

    ready_status = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="opensandbox-snapshots:snap-ready",
        reason="snapshot_runtime_ready",
        message="Docker snapshot image created successfully.",
    )

    def create_snapshot(snapshot_id: str, sandbox_id: str, **kwargs):
        runtime.calls.append((snapshot_id, sandbox_id))
        return ready_status

    runtime.create_snapshot = create_snapshot
    created = service.create_snapshot("sbx-001", CreateSnapshotRequest(name="checkpoint"))

    failed_record = repo.get(created.id)
    assert failed_record is not None
    failed_record.status = SnapshotStatusRecord(
        state=SnapshotState.FAILED,
        reason="external_transition",
        message="Snapshot was transitioned by another worker.",
    )
    repo.update(failed_record)

    service._create_snapshot_worker(_snapshot_record(created.id, SnapshotState.CREATING))

    stored = repo.get(created.id)
    assert stored is not None
    assert stored.status.state == SnapshotState.FAILED
    assert stored.status.reason == "external_transition"
    assert stored.restore_config.image is None


def test_snapshot_service_close_shuts_down_executor(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    executor = CapturingExecutor()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=StubSnapshotRuntime(),
        snapshot_executor=executor,
    )

    service.close()

    assert executor.shutdown_called is True
    assert executor.shutdown_wait is True


def test_snapshot_service_propagates_missing_sandbox(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    service = PersistedSnapshotService(repo, StubSandboxService())

    with pytest.raises(HTTPException) as exc_info:
        service.create_snapshot("missing", CreateSnapshotRequest())

    assert exc_info.value.status_code == 404


def test_snapshot_service_returns_501_when_runtime_is_not_supported(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    service = PersistedSnapshotService(repo, StubSandboxService(), snapshot_runtime=NoopSnapshotRuntime())

    with pytest.raises(HTTPException) as exc_info:
        service.create_snapshot("sbx-001", CreateSnapshotRequest())

    assert exc_info.value.status_code == 501
    assert exc_info.value.detail["code"] == "SNAPSHOT::NOT_IMPLEMENTED"


def test_snapshot_service_recovers_creating_snapshot_with_existing_artifact(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    repo.create(_snapshot_record("snap-ready", SnapshotState.CREATING))
    runtime = StubSnapshotRuntime()
    runtime.inspect_status_by_snapshot_id["snap-ready"] = SnapshotRuntimeStatus(
        state=SnapshotState.READY,
        image="opensandbox-snapshots:snap-ready",
        reason="snapshot_recovery_ready",
        message="Recovered snapshot image after server restart.",
    )

    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    recovered = repo.get("snap-ready")
    assert recovered is not None
    assert recovered.status.state == SnapshotState.READY
    assert recovered.restore_config.image == "opensandbox-snapshots:snap-ready"


def test_snapshot_service_recovers_creating_snapshot_without_artifact(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    repo.create(_snapshot_record("snap-missing", SnapshotState.CREATING))
    runtime = StubSnapshotRuntime()

    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    recovered = repo.get("snap-missing")
    assert recovered is not None
    assert recovered.status.state == SnapshotState.FAILED
    assert recovered.status.reason == "snapshot_recovery_missing_image"


def test_snapshot_service_recovers_deleting_snapshot(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    repo.create(
        _snapshot_record(
            "snap-delete",
            SnapshotState.DELETING,
            image="opensandbox-snapshots:snap-delete",
        )
    )
    runtime = StubSnapshotRuntime()

    PersistedSnapshotService(repo, StubSandboxService(), snapshot_runtime=runtime)

    assert runtime.delete_calls == [("snap-delete", "opensandbox-snapshots:snap-delete")]
    assert repo.get("snap-delete") is None


def test_sqlite_startup_recovers_more_than_distributed_worker_limit(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    records = [
        _snapshot_record(
            f"snap-delete-{index}",
            SnapshotState.DELETING,
            image=f"opensandbox-snapshots:snap-delete-{index}",
        )
        for index in range(3)
    ]
    for record in records:
        repo.create(record)
    runtime = StubSnapshotRuntime()

    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    assert sorted(call[0] for call in runtime.delete_calls) == sorted(
        record.id for record in records
    )
    assert all(repo.get(record.id) is None for record in records)


def test_sqlite_startup_recovers_deleting_backlog_across_page_boundary(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    records = [
        _snapshot_record(
            f"snap-delete-page-{index}",
            SnapshotState.DELETING,
            image=f"opensandbox-snapshots:snap-delete-page-{index}",
        )
        for index in range(205)
    ]
    for record in records:
        repo.create(record)
    runtime = StubSnapshotRuntime()

    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    assert len(runtime.delete_calls) == len(records)
    assert all(repo.get(record.id) is None for record in records)


def test_sqlite_startup_recovers_creating_backlog_across_page_boundary(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    records = [
        _snapshot_record(f"snap-create-page-{index}", SnapshotState.CREATING)
        for index in range(205)
    ]
    for record in records:
        repo.create(record)
    runtime = ReadyCreateRuntime()
    listed_pages: list[int] = []
    original_list = repo.list
    original_recover = runtime.recover_snapshot

    def record_page(query: SnapshotListQuery):
        listed_pages.append(query.page)
        return original_list(query)

    def assert_all_pages_collected(*args, **kwargs):
        assert listed_pages == [1, 2]
        return original_recover(*args, **kwargs)

    repo.list = record_page
    runtime.recover_snapshot = assert_all_pages_collected

    PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
    )

    assert len(runtime.recover_calls) == len(records)
    assert all(
        (stored := repo.get(record.id)) is not None
        and stored.status.state == SnapshotState.READY
        for record in records
    )


def test_sqlite_startup_continues_creating_backlog_after_slots_free(tmp_path) -> None:
    repo = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    records = [
        _snapshot_record(f"snap-create-{index}", SnapshotState.CREATING)
        for index in range(3)
    ]
    for record in records:
        repo.create(record)
    runtime = BlockingRecoveryRuntime()
    service = PersistedSnapshotService(
        repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        recovery_interval_seconds=0.02,
    )

    try:
        assert runtime.two_started.wait(timeout=2)
        assert runtime.three_started.is_set() is False
        runtime.release.set()
        assert runtime.three_started.wait(timeout=2)

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = [repo.get(record.id) for record in records]
            if all(item is not None and item.status.state == SnapshotState.READY for item in stored):
                break
            time.sleep(0.01)
        else:
            pytest.fail("SQLite startup recovery did not drain the Creating backlog")
    finally:
        runtime.release.set()
        service.close()


@pytest.mark.parametrize("state", [SnapshotState.CREATING, SnapshotState.DELETING])
def test_sqlite_startup_retries_after_previous_owner_lease_expires(
    tmp_path,
    state: SnapshotState,
) -> None:
    db_path = tmp_path / "snapshots.db"
    first_repo = SQLiteSnapshotRepository(db_path)
    record = _snapshot_record(
        f"snap-stale-startup-{state.value.lower()}",
        state,
        image=(
            f"opensandbox-snapshots:snap-stale-startup-{state.value.lower()}"
            if state == SnapshotState.DELETING
            else None
        ),
    )
    first_repo.create(record)
    old_claim = first_repo.claim_operation(
        record.id,
        state,
        "stopped-server",
        timedelta(seconds=0.1),
    )
    assert old_claim is not None
    first_repo.close()

    second_repo = SQLiteSnapshotRepository(db_path)
    runtime = ReadyCreateRuntime() if state == SnapshotState.CREATING else StubSnapshotRuntime()
    service = PersistedSnapshotService(
        second_repo,
        StubSandboxService(),
        snapshot_runtime=runtime,
        snapshot_executor=ImmediateExecutor(),
        operation_owner="replacement-server",
        operation_lease_seconds=0.2,
        lease_renew_interval_seconds=0.05,
        recovery_interval_seconds=0.01,
    )

    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = second_repo.get(record.id)
            if state == SnapshotState.CREATING:
                if stored is not None and stored.status.state == SnapshotState.READY:
                    break
            elif stored is None:
                break
            time.sleep(0.01)
        else:
            pytest.fail(f"SQLite did not take over stale {state.value} startup lease")

        if state == SnapshotState.CREATING:
            assert isinstance(runtime, ReadyCreateRuntime)
            assert runtime.recover_calls == [record.id]
        else:
            assert runtime.delete_calls == [(record.id, record.restore_config.image)]
    finally:
        service.close()

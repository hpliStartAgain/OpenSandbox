# Copyright 2026 Alibaba Group Holding Ltd.
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

from concurrent.futures import Future, ThreadPoolExecutor
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
import os
from threading import Barrier, Event
import time

import psycopg
import pytest
from pydantic import SecretStr

from opensandbox_server.api.schema import (
    CreateSandboxRequest,
    CreateSnapshotRequest,
    ListSnapshotsRequest,
    ResourceLimits,
)
from opensandbox_server.config import (
    AppConfig,
    PostgreSQLStoreConfig,
    RuntimeConfig,
    StoreConfig,
)
from opensandbox_server.repositories.snapshots.factory import create_snapshot_repository
from opensandbox_server.repositories.snapshots.postgresql import PostgreSQLSnapshotRepository
from opensandbox_server.services.snapshot_models import SnapshotState
from opensandbox_server.services.snapshot_restore import resolve_sandbox_image_from_request
from opensandbox_server.services.snapshot_runtime import SnapshotRuntimeStatus
from opensandbox_server.services.snapshot_service import PersistedSnapshotService
from tests.snapshot_repository_contract import (
    SnapshotRepositoryContract,
    snapshot_record,
)

TEST_POSTGRESQL_DSN_ENV_VAR = "OPENSANDBOX_TEST_POSTGRESQL_DSN"


@pytest.fixture(scope="module")
def postgresql_dsn() -> str:
    dsn = os.environ.get(TEST_POSTGRESQL_DSN_ENV_VAR)
    if not dsn:
        pytest.skip(f"{TEST_POSTGRESQL_DSN_ENV_VAR} is not set")
    return dsn


def _repository(dsn: str) -> PostgreSQLSnapshotRepository:
    return PostgreSQLSnapshotRepository(
        dsn,
        min_pool_size=0,
        max_pool_size=4,
        connect_timeout_seconds=5,
        pool_timeout_seconds=5,
    )


class _ImmediateExecutor:
    def submit(self, fn, *args, **kwargs) -> Future:
        future = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001
            future.set_exception(exc)
        return future

    def shutdown(self, wait: bool = True) -> None:
        return None


class _ReadyRuntime:
    def __init__(self) -> None:
        self.recover_called = Event()
        self.delete_called = Event()

    def supports_create_snapshot(self) -> bool:
        return True

    def create_snapshot_unsupported_message(self) -> str:
        return ""

    def create_snapshot(self, snapshot_id: str, sandbox_id: str, **kwargs):
        return SnapshotRuntimeStatus(
            state=SnapshotState.READY,
            image=f"registry.example.com/snapshots/{snapshot_id}:ready",
            reason="snapshot_runtime_ready",
        )

    def recover_snapshot(self, snapshot_id: str, sandbox_id: str, image=None, **kwargs):
        self.recover_called.set()
        return self.create_snapshot(snapshot_id, sandbox_id, **kwargs)

    def get_snapshot_status(self, snapshot_id: str):
        return None

    def inspect_snapshot(self, snapshot_id: str, image=None, **kwargs):
        return SnapshotRuntimeStatus(state=SnapshotState.CREATING)

    def delete_snapshot(self, snapshot_id: str, image=None, **kwargs) -> None:
        self.delete_called.set()
        return None


class _SandboxService:
    @staticmethod
    def get_sandbox(sandbox_id: str):
        return {"id": sandbox_id, "status": {"state": "Running"}}


class TestPostgreSQLSnapshotRepositoryContract(SnapshotRepositoryContract):
    @pytest.fixture
    def repository(self, postgresql_dsn: str) -> Iterator[PostgreSQLSnapshotRepository]:
        repo = _repository(postgresql_dsn)
        try:
            with psycopg.connect(postgresql_dsn) as conn:
                conn.execute("TRUNCATE TABLE snapshots")
            yield repo
        finally:
            repo.close()


def test_postgresql_factory_selects_backend(postgresql_dsn: str) -> None:
    config = AppConfig(
        runtime=RuntimeConfig(type="docker", execd_image="opensandbox/execd:test"),
        store=StoreConfig(
            type="postgresql",
            postgresql=PostgreSQLStoreConfig(
                dsn=SecretStr(postgresql_dsn),
                min_pool_size=0,
                max_pool_size=2,
            ),
        ),
    )

    repo = create_snapshot_repository(config)
    try:
        assert isinstance(repo, PostgreSQLSnapshotRepository)
    finally:
        repo.close()


@pytest.mark.asyncio
async def test_two_server_instances_share_snapshot_get_list_and_restore(
    postgresql_dsn: str,
    monkeypatch,
) -> None:
    first_repo = _repository(postgresql_dsn)
    second_repo = _repository(postgresql_dsn)
    first_service = PersistedSnapshotService(
        first_repo,
        _SandboxService(),
        snapshot_runtime=_ReadyRuntime(),
        snapshot_executor=_ImmediateExecutor(),
        recover_unfinished_snapshots=False,
        operation_owner="server-a",
    )
    second_service = PersistedSnapshotService(
        second_repo,
        _SandboxService(),
        snapshot_runtime=_ReadyRuntime(),
        snapshot_executor=_ImmediateExecutor(),
        recover_unfinished_snapshots=False,
        operation_owner="server-b",
    )
    try:
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute("TRUNCATE TABLE snapshots")

        created = first_service.create_snapshot(
            "sbx-001",
            CreateSnapshotRequest(name="shared-snapshot"),
        )

        fetched = second_service.get_snapshot(created.id)
        listed = second_service.list_snapshots(ListSnapshotsRequest())
        assert fetched.status.state == SnapshotState.READY.value
        assert [item.id for item in listed.items] == [created.id]

        monkeypatch.setattr(
            "opensandbox_server.services.snapshot_restore.get_snapshot_repository",
            lambda: second_repo,
        )
        request = CreateSandboxRequest(
            snapshotId=created.id,
            resourceLimits=ResourceLimits(root={"cpu": "500m"}),
        )
        resolved = await resolve_sandbox_image_from_request(request)
        assert resolved.image is not None
        assert resolved.image.uri.endswith(f"/{created.id}:ready")
    finally:
        first_service.close()
        second_service.close()
        first_repo.close()
        second_repo.close()


@pytest.mark.parametrize("state", [SnapshotState.CREATING, SnapshotState.DELETING])
def test_running_standby_takes_over_expired_operation_lease(
    postgresql_dsn: str,
    state: SnapshotState,
) -> None:
    first_repo = _repository(postgresql_dsn)
    second_repo = _repository(postgresql_dsn)
    runtime = _ReadyRuntime()
    standby: PersistedSnapshotService | None = None
    try:
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute("TRUNCATE TABLE snapshots")
        record = snapshot_record(
            f"snap-takeover-{state.value.lower()}",
            "sbx-001",
            datetime.now(timezone.utc),
            state,
        )
        first_repo.create(record)
        first_claim = first_repo.claim_operation(
            record.id,
            state,
            "server-a",
            timedelta(seconds=30),
        )
        assert first_claim is not None

        standby = PersistedSnapshotService(
            second_repo,
            _SandboxService(),
            snapshot_runtime=runtime,
            operation_owner="server-b",
            operation_lease_seconds=1,
            lease_renew_interval_seconds=0.2,
            recovery_interval_seconds=0.02,
        )
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute(
                "UPDATE snapshots SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' "
                "WHERE id = %s",
                (record.id,),
            )

        expected_call = (
            runtime.recover_called
            if state == SnapshotState.CREATING
            else runtime.delete_called
        )
        assert expected_call.wait(timeout=2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stored = first_repo.get(record.id)
            if state == SnapshotState.CREATING and stored is not None:
                if stored.status.state == SnapshotState.READY:
                    break
            elif state == SnapshotState.DELETING and stored is None:
                break
            time.sleep(0.01)
        else:
            pytest.fail(f"standby did not finish takeover for {state.value}")

        stored = first_repo.get(record.id)
        if state == SnapshotState.CREATING:
            assert stored is not None
            assert stored.status.state == SnapshotState.READY
            assert stored.operation_generation == first_claim.operation_generation + 1
        else:
            assert stored is None
    finally:
        if standby is not None:
            standby.close()
        first_repo.close()
        second_repo.close()


def test_postgresql_schema_initialization_is_concurrent_safe(
    postgresql_dsn: str,
    monkeypatch,
) -> None:
    with psycopg.connect(postgresql_dsn) as conn:
        conn.execute("DROP TABLE IF EXISTS snapshots")

    barrier = Barrier(2)
    initialize_schema = PostgreSQLSnapshotRepository._initialize_schema

    def initialize_schema_concurrently(repo: PostgreSQLSnapshotRepository) -> None:
        barrier.wait(timeout=5)
        initialize_schema(repo)

    monkeypatch.setattr(
        PostgreSQLSnapshotRepository,
        "_initialize_schema",
        initialize_schema_concurrently,
    )

    repositories: list[PostgreSQLSnapshotRepository] = []
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(_repository, postgresql_dsn) for _ in range(2)]
            errors: list[BaseException] = []
            for future in futures:
                try:
                    repositories.append(future.result())
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise errors[0]

        with psycopg.connect(postgresql_dsn) as conn:
            row = conn.execute("SELECT to_regclass('snapshots')").fetchone()
        assert row is not None
        table_name = row[0]
        assert table_name == "snapshots"
    finally:
        for repo in repositories:
            repo.close()


def test_postgresql_compare_and_swap_has_one_winner(postgresql_dsn: str) -> None:
    repositories: list[PostgreSQLSnapshotRepository] = []
    try:
        first_repo = _repository(postgresql_dsn)
        repositories.append(first_repo)
        second_repo = _repository(postgresql_dsn)
        repositories.append(second_repo)
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute("TRUNCATE TABLE snapshots")

        now = datetime.now(timezone.utc)
        original = snapshot_record("snap-race", "sbx-001", now)
        ready = snapshot_record(
            original.id,
            original.source_sandbox_id,
            original.created_at,
            SnapshotState.READY,
        )
        failed = snapshot_record(
            original.id,
            original.source_sandbox_id,
            original.created_at,
            SnapshotState.FAILED,
        )
        first_repo.create(original)
        barrier = Barrier(2)

        def update(repo, record) -> bool:
            barrier.wait(timeout=5)
            return repo.update_if_state(record, SnapshotState.CREATING)

        with ThreadPoolExecutor(max_workers=2) as executor:
            ready_future = executor.submit(update, first_repo, ready)
            failed_future = executor.submit(update, second_repo, failed)
            results = [ready_future.result(), failed_future.result()]

        assert sorted(results) == [False, True]
        winning_state = SnapshotState.READY if results[0] else SnapshotState.FAILED
        stored = first_repo.get(original.id)
        assert stored is not None
        assert stored.status.state == winning_state
    finally:
        for repo in repositories:
            repo.close()


def test_postgresql_operation_claim_has_one_winner(postgresql_dsn: str) -> None:
    repositories: list[PostgreSQLSnapshotRepository] = []
    try:
        first_repo = _repository(postgresql_dsn)
        repositories.append(first_repo)
        second_repo = _repository(postgresql_dsn)
        repositories.append(second_repo)
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute("TRUNCATE TABLE snapshots")

        record = snapshot_record(
            "snap-claim-race",
            "sbx-001",
            datetime.now(timezone.utc),
        )
        first_repo.create(record)
        barrier = Barrier(2)

        def claim(repo, owner: str):
            barrier.wait(timeout=5)
            return repo.claim_operation(
                record.id,
                SnapshotState.CREATING,
                owner,
                timedelta(seconds=30),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(claim, first_repo, "server-a")
            second_future = executor.submit(claim, second_repo, "server-b")
            claims = [first_future.result(), second_future.result()]

        winners = [claim for claim in claims if claim is not None]
        assert len(winners) == 1
        assert winners[0].operation_generation == 1
        assert winners[0].operation_attempt == 1
        assert winners[0].lease_owner in {"server-a", "server-b"}
        assert winners[0].lease_expires_at is not None
    finally:
        for repo in repositories:
            repo.close()


def test_postgresql_lease_renew_expiry_takeover_and_fencing(
    postgresql_dsn: str,
) -> None:
    first_repo = _repository(postgresql_dsn)
    second_repo = _repository(postgresql_dsn)
    try:
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute("TRUNCATE TABLE snapshots")

        record = snapshot_record(
            "snap-takeover",
            "sbx-001",
            datetime.now(timezone.utc),
        )
        first_repo.create(record)
        first_claim = first_repo.claim_operation(
            record.id,
            SnapshotState.CREATING,
            "server-a",
            timedelta(seconds=30),
        )
        assert first_claim is not None
        assert first_repo.renew_operation(
            record.id,
            SnapshotState.CREATING,
            "server-a",
            first_claim.operation_generation,
            timedelta(seconds=30),
        ) is True
        assert second_repo.claim_operation(
            record.id,
            SnapshotState.CREATING,
            "server-b",
            timedelta(seconds=30),
        ) is None

        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute(
                "UPDATE snapshots SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' "
                "WHERE id = %s",
                (record.id,),
            )

        second_claim = second_repo.claim_operation(
            record.id,
            SnapshotState.CREATING,
            "server-b",
            timedelta(seconds=30),
        )
        assert second_claim is not None
        assert second_claim.operation_generation == first_claim.operation_generation + 1
        assert second_claim.operation_attempt == first_claim.operation_attempt + 1
        assert first_repo.renew_operation(
            record.id,
            SnapshotState.CREATING,
            "server-a",
            first_claim.operation_generation,
            timedelta(seconds=30),
        ) is False

        stale_ready = snapshot_record(
            record.id,
            record.source_sandbox_id,
            record.created_at,
            SnapshotState.READY,
        )
        stale_ready.operation_generation = first_claim.operation_generation
        stale_ready.operation_attempt = first_claim.operation_attempt
        assert first_repo.update_if_operation_owner(
            stale_ready,
            SnapshotState.CREATING,
            "server-a",
            first_claim.operation_generation,
        ) is False

        ready = snapshot_record(
            record.id,
            record.source_sandbox_id,
            record.created_at,
            SnapshotState.READY,
        )
        ready.operation_generation = second_claim.operation_generation
        ready.operation_attempt = second_claim.operation_attempt
        assert second_repo.update_if_operation_owner(
            ready,
            SnapshotState.CREATING,
            "server-b",
            second_claim.operation_generation,
        ) is True
        stored = first_repo.get(record.id)
        assert stored is not None
        assert stored.status.state == SnapshotState.READY
        assert stored.lease_owner is None
        assert stored.lease_expires_at is None

        deleting = snapshot_record(
            record.id,
            record.source_sandbox_id,
            record.created_at,
            SnapshotState.DELETING,
        )
        deleting.operation_generation = stored.operation_generation
        deleting.operation_attempt = stored.operation_attempt
        assert second_repo.update_if_state(deleting, SnapshotState.READY) is True
        first_delete_claim = first_repo.claim_operation(
            record.id,
            SnapshotState.DELETING,
            "server-a",
            timedelta(seconds=30),
        )
        assert first_delete_claim is not None
        with psycopg.connect(postgresql_dsn) as conn:
            conn.execute(
                "UPDATE snapshots SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' "
                "WHERE id = %s",
                (record.id,),
            )
        second_delete_claim = second_repo.claim_operation(
            record.id,
            SnapshotState.DELETING,
            "server-b",
            timedelta(seconds=30),
        )
        assert second_delete_claim is not None
        assert first_repo.delete_if_operation_owner(
            record.id,
            SnapshotState.DELETING,
            "server-a",
            first_delete_claim.operation_generation,
        ) is False
        assert second_repo.delete_if_operation_owner(
            record.id,
            SnapshotState.DELETING,
            "server-b",
            second_delete_claim.operation_generation,
        ) is True
        assert first_repo.get(record.id) is None
    finally:
        first_repo.close()
        second_repo.close()


def test_postgresql_schema_upgrade_adds_operation_lease_columns(
    postgresql_dsn: str,
) -> None:
    with psycopg.connect(postgresql_dsn) as conn:
        conn.execute("DROP TABLE IF EXISTS snapshots")
        conn.execute(
            """
            CREATE TABLE snapshots (
                id TEXT PRIMARY KEY,
                source_sandbox_id TEXT NOT NULL,
                namespace TEXT DEFAULT NULL,
                name TEXT,
                description TEXT,
                restore_config JSONB NOT NULL,
                state TEXT NOT NULL,
                reason TEXT,
                message TEXT,
                last_transition_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """
        )

    repo = _repository(postgresql_dsn)
    repo.close()

    with psycopg.connect(postgresql_dsn) as conn:
        columns = {
            row[0]: (row[1], row[2])
            for row in conn.execute(
                """
                SELECT column_name, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_name = 'snapshots'
                """
            ).fetchall()
        }
    assert columns["operation_generation"][0] == "NO"
    assert columns["operation_attempt"][0] == "NO"
    assert "lease_owner" in columns
    assert "lease_expires_at" in columns


def test_postgresql_close_releases_pool(postgresql_dsn: str) -> None:
    repo = _repository(postgresql_dsn)

    repo.close()

    assert repo._pool.closed is True


def test_postgresql_row_timestamps_are_normalized_to_utc() -> None:
    local_timezone = timezone(timedelta(hours=8))
    local_time = datetime(2026, 1, 2, 8, 0, tzinfo=local_timezone)

    record = PostgreSQLSnapshotRepository._row_to_record(
        {
            "id": "snap-timezone",
            "source_sandbox_id": "sbx-001",
            "namespace": None,
            "name": None,
            "description": None,
            "restore_config": {"image": None},
            "state": SnapshotState.CREATING.value,
            "reason": None,
            "message": None,
            "last_transition_at": local_time,
            "created_at": local_time,
            "updated_at": local_time,
            "operation_generation": 0,
            "lease_owner": None,
            "lease_expires_at": None,
            "operation_attempt": 0,
        }
    )

    expected = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
    last_transition_at = record.status.last_transition_at
    assert last_transition_at is not None
    assert last_transition_at == expected
    assert last_transition_at.tzinfo is timezone.utc
    assert record.created_at == expected
    assert record.created_at.tzinfo is timezone.utc
    assert record.updated_at == expected
    assert record.updated_at.tzinfo is timezone.utc

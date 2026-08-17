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

"""
API routes for OpenSandbox DevOps diagnostics.

Requests that include ``scope`` target the stable Diagnostics API and return an
inline JSON descriptor. Requests without ``scope`` preserve the deprecated
DevOps plain-text behavior for legacy humans, agents, and CLI clients.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse

from opensandbox_server.api.lifecycle import sandbox_service

logger = logging.getLogger(__name__)
router = APIRouter(tags=["DevOps"])


def _diagnostic_inline_response(
    sandbox_id: str,
    kind: str,
    scope: str,
    content: str,
    warnings: list[str] | None = None,
) -> JSONResponse:
    payload: dict = {
        "sandboxId": sandbox_id,
        "kind": kind,
        "scope": scope,
        "delivery": "inline",
        "contentType": "text/plain; charset=utf-8",
        "content": content,
        "contentLength": len(content.encode("utf-8")),
        "truncated": False,
    }
    if warnings:
        payload["warnings"] = warnings
    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)


def _unsupported_scope_response(
    kind: str,
    scope: str,
    supported: tuple[str, ...],
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": "DIAGNOSTICS_SCOPE_UNSUPPORTED",
            "message": (
                f"Unsupported {kind} diagnostics scope {scope!r}. "
                f"Supported scopes: {', '.join(supported)}."
            ),
        },
    )


def _deprecated_plain_text_response(content: str) -> PlainTextResponse:
    return PlainTextResponse(
        content=content,
        headers={"Deprecation": "true"},
    )


@router.get(
    "/sandboxes/{sandbox_id}/diagnostics/logs",
    response_model=None,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Stable JSON descriptor, or deprecated text when scope is omitted",
            "content": {"application/json": {}, "text/plain": {}},
        },
        400: {"description": "Unsupported diagnostics scope"},
        404: {"description": "Sandbox not found"},
    },
)
def get_sandbox_logs(
    sandbox_id: str,
    scope: Optional[str] = Query(
        None,
        description="Required for stable Diagnostics JSON responses. Omit only for deprecated plain-text logs.",
    ),
    tail: int = Query(
        100,
        ge=1,
        le=10000,
        deprecated=True,
        description="Deprecated plain-text logs only. Number of trailing log lines.",
    ),
    since: Optional[str] = Query(
        None,
        deprecated=True,
        description="Deprecated plain-text logs only. Only return logs newer than this duration (e.g. 10m, 1h).",
    ),
    container: Optional[str] = Query(
        None,
        deprecated=True,
        description=(
            "Deprecated plain-text logs only. Container name to read logs from. "
            "Defaults to the canonical user container (typically 'sandbox') when "
            "the runtime supports multi-container pods."
        ),
    ),
) -> JSONResponse | PlainTextResponse:
    """Retrieve diagnostic logs for a sandbox."""
    if scope is not None:
        normalized_scope = scope.strip().lower()
        supported = ("container", "all")
        if normalized_scope not in supported:
            return _unsupported_scope_response("logs", scope, supported)
        text = sandbox_service.get_sandbox_logs(
            sandbox_id, tail=tail, since=since, container=container
        )
        warnings = None
        if normalized_scope == "all":
            warnings = ["This backend currently contributes sandbox container logs only."]
        return _diagnostic_inline_response(
            sandbox_id,
            "logs",
            normalized_scope,
            text,
            warnings=warnings,
        )
    text = sandbox_service.get_sandbox_logs(
        sandbox_id, tail=tail, since=since, container=container
    )
    return _deprecated_plain_text_response(text)


@router.get(
    "/sandboxes/{sandbox_id}/diagnostics/inspect",
    response_class=PlainTextResponse,
    status_code=status.HTTP_200_OK,
    deprecated=True,
    responses={
        200: {"description": "Container inspection as plain text", "content": {"text/plain": {}}},
        404: {"description": "Sandbox not found"},
    },
)
def get_sandbox_inspect(sandbox_id: str) -> PlainTextResponse:
    """Retrieve detailed inspection info for a sandbox container."""
    text = sandbox_service.get_sandbox_inspect(sandbox_id)
    return PlainTextResponse(content=text)


@router.get(
    "/sandboxes/{sandbox_id}/diagnostics/events",
    response_model=None,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Stable JSON descriptor, or deprecated text when scope is omitted",
            "content": {"application/json": {}, "text/plain": {}},
        },
        400: {"description": "Unsupported diagnostics scope"},
        404: {"description": "Sandbox not found"},
    },
)
def get_sandbox_events(
    sandbox_id: str,
    scope: Optional[str] = Query(
        None,
        description="Required for stable Diagnostics JSON responses. Omit only for deprecated plain-text events.",
    ),
    limit: int = Query(
        50,
        ge=1,
        le=500,
        deprecated=True,
        description="Deprecated plain-text events only. Maximum number of events to return.",
    ),
) -> JSONResponse | PlainTextResponse:
    """Retrieve diagnostic events for a sandbox."""
    if scope is not None:
        normalized_scope = scope.strip().lower()
        supported = ("runtime", "lifecycle", "all")
        if normalized_scope not in supported:
            return _unsupported_scope_response("events", scope, supported)
        text = sandbox_service.get_sandbox_events(sandbox_id, limit=limit)
        warnings = None
        if normalized_scope != "runtime":
            warnings = [
                "This backend currently represents lifecycle/all scopes with runtime events."
            ]
        return _diagnostic_inline_response(
            sandbox_id,
            "events",
            normalized_scope,
            text,
            warnings=warnings,
        )
    text = sandbox_service.get_sandbox_events(sandbox_id, limit=limit)
    return _deprecated_plain_text_response(text)


@router.get(
    "/sandboxes/{sandbox_id}/diagnostics/summary",
    response_class=PlainTextResponse,
    status_code=status.HTTP_200_OK,
    deprecated=True,
    responses={
        200: {"description": "Combined diagnostics summary as plain text", "content": {"text/plain": {}}},
        404: {"description": "Sandbox not found"},
    },
)
def get_sandbox_diagnostics_summary(
    sandbox_id: str,
    tail: int = Query(50, ge=1, le=10000, description="Number of trailing log lines"),
    event_limit: int = Query(20, ge=1, le=500, description="Maximum number of events"),
) -> PlainTextResponse:
    """One-shot diagnostics summary: inspect + events + logs."""
    sections: list[str] = []

    sections.append("=" * 72)
    sections.append("SANDBOX DIAGNOSTICS SUMMARY")
    sections.append(f"Sandbox ID: {sandbox_id}")
    sections.append("=" * 72)

    # Inspect — let HTTPException (e.g. 404) propagate so callers get a proper error
    sections.append("")
    sections.append("-" * 40)
    sections.append("INSPECT")
    sections.append("-" * 40)
    try:
        sections.append(sandbox_service.get_sandbox_inspect(sandbox_id))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to collect sandbox inspect diagnostics for %s", sandbox_id)
        sections.append("[error] Failed to collect inspect diagnostics.")

    # Events
    sections.append("")
    sections.append("-" * 40)
    sections.append("EVENTS")
    sections.append("-" * 40)
    try:
        sections.append(sandbox_service.get_sandbox_events(sandbox_id, limit=event_limit))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to collect sandbox event diagnostics for %s", sandbox_id)
        sections.append("[error] Failed to collect event diagnostics.")

    # Logs
    sections.append("")
    sections.append("-" * 40)
    sections.append("LOGS (last {} lines)".format(tail))
    sections.append("-" * 40)
    try:
        sections.append(sandbox_service.get_sandbox_logs(sandbox_id, tail=tail))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to collect sandbox log diagnostics for %s", sandbox_id)
        sections.append("[error] Failed to collect log diagnostics.")

    return PlainTextResponse(content="\n".join(sections) + "\n")

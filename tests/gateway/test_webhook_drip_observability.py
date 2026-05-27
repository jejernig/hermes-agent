"""Tests for optional Drip observability on generic webhook deliveries."""

import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.webhook import WebhookAdapter, _INSECURE_NO_AUTH


def _make_adapter(routes, **extra_kw) -> WebhookAdapter:
    extra = {"host": "127.0.0.1", "port": 0, "routes": routes}
    extra.update(extra_kw)
    config = PlatformConfig(enabled=True, extra=extra)
    return WebhookAdapter(config)


def _create_app(adapter: WebhookAdapter) -> web.Application:
    app = web.Application()
    app.router.add_get("/health", adapter._handle_health)
    app.router.add_post("/webhooks/{route_name}", adapter._handle_webhook)
    return app


@pytest.mark.asyncio
async def test_accepted_webhook_emits_sanitized_drip_envelope(monkeypatch):
    routes = {
        "github-pr-agent": {
            "secret": _INSECURE_NO_AUTH,
            "events": ["pull_request"],
            "prompt": "Review PR {pull_request.number}",
        }
    }
    adapter = _make_adapter(
        routes,
        drip_observability={
            "enabled": True,
            "source_service": "hermes-webhook",
            "source_vm": "mac",
            "event_category": "webhook",
        },
    )

    handled = []

    async def _capture_handle_message(event):
        handled.append(event)

    emitted = []

    async def _capture_drip_envelope(envelope):
        emitted.append(envelope)

    adapter.handle_message = _capture_handle_message
    monkeypatch.setattr(adapter, "_post_drip_envelope", _capture_drip_envelope, raising=False)

    payload = {
        "action": "opened",
        "repository": {"full_name": "Team-Teddy-Development/example"},
        "pull_request": {
            "number": 42,
            "title": "Add observability",
            "html_url": "https://github.com/Team-Teddy-Development/example/pull/42",
        },
        "sender": {"login": "octocat"},
        "secret": "must-not-leak",
        "token": "must-not-leak",
    }

    async with TestClient(TestServer(_create_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/github-pr-agent",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-drip-1",
            },
        )
        assert resp.status == 202

    await asyncio.sleep(0.05)

    assert len(handled) == 1
    assert len(emitted) == 1
    envelope = emitted[0]
    assert envelope["source_service"] == "hermes-webhook"
    assert envelope["source_vm"] == "mac"
    assert envelope["event_category"] == "webhook"
    assert envelope["event_type"] == "pull_request.accepted"
    assert envelope["severity"] == "info"
    assert envelope["correlation_id"] == "delivery-drip-1"
    assert envelope["idempotency_key"] == "webhook-github-pr-agent-delivery-drip-1-accepted"
    assert envelope["payload"] == {
        "route": "github-pr-agent",
        "event": "pull_request",
        "outcome": "accepted",
        "delivery_id": "delivery-drip-1",
        "repository": "Team-Teddy-Development/example",
        "pr_number": 42,
        "pr_title": "Add observability",
        "pr_url": "https://github.com/Team-Teddy-Development/example/pull/42",
        "sender": "octocat",
    }
    assert "must-not-leak" not in json.dumps(envelope)


@pytest.mark.asyncio
async def test_ignored_webhook_emits_drip_envelope(monkeypatch):
    adapter = _make_adapter(
        {
            "github-pr-agent": {
                "secret": _INSECURE_NO_AUTH,
                "events": ["pull_request"],
                "prompt": "ignored",
            }
        },
        drip_observability={"enabled": True},
    )
    emitted = []

    async def _capture_drip_envelope(envelope):
        emitted.append(envelope)

    monkeypatch.setattr(adapter, "_post_drip_envelope", _capture_drip_envelope)

    async with TestClient(TestServer(_create_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/github-pr-agent",
            json={"repository": {"full_name": "Team-Teddy-Development/example"}},
            headers={
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "delivery-ignored-1",
            },
        )
        assert resp.status == 200
        assert (await resp.json())["status"] == "ignored"

    await asyncio.sleep(0.05)
    assert len(emitted) == 1
    assert emitted[0]["event_type"] == "push.ignored"
    assert emitted[0]["severity"] == "info"
    assert emitted[0]["correlation_id"] == "delivery-ignored-1"
    assert emitted[0]["payload"]["outcome"] == "ignored"


@pytest.mark.asyncio
async def test_rejected_webhook_emits_drip_envelope_without_body_secrets(monkeypatch):
    adapter = _make_adapter(
        {
            "github-pr-agent": {
                "secret": "real-secret",
                "events": ["pull_request"],
                "prompt": "rejected",
            }
        },
        drip_observability={"enabled": True},
    )
    emitted = []

    async def _capture_drip_envelope(envelope):
        emitted.append(envelope)

    monkeypatch.setattr(adapter, "_post_drip_envelope", _capture_drip_envelope)

    async with TestClient(TestServer(_create_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/github-pr-agent",
            json={"secret": "must-not-leak"},
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-rejected-1",
                "X-Hub-Signature-256": "sha256=bad",
            },
        )
        assert resp.status == 401

    await asyncio.sleep(0.05)
    assert len(emitted) == 1
    assert emitted[0]["event_type"] == "pull_request.rejected"
    assert emitted[0]["severity"] == "warning"
    assert emitted[0]["correlation_id"] == "delivery-rejected-1"
    assert emitted[0]["payload"] == {
        "route": "github-pr-agent",
        "event": "pull_request",
        "outcome": "rejected",
        "delivery_id": "delivery-rejected-1",
        "reason": "invalid_signature",
    }
    assert "must-not-leak" not in json.dumps(emitted[0])

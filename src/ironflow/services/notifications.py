"""Notification channels and the event subscriber that drives them.

Channels implement the :class:`~ironflow.core.interfaces.Notifier` protocol and
are attached to the event bus, so the runner never imports Slack or SMTP.  A
channel that fails is logged and skipped: a broken webhook must never fail a
data load.

Security notes
--------------
* Webhook URLs are resolved through the secret resolver and checked against the
  operator's network policy - before the request, and again at connect time
  through the guarded client - exactly like any other outbound HTTP call.
* Payloads are passed through :func:`redact_mapping` before sending, so a
  connection string that found its way into an error context does not get
  posted into a chat channel.
* SMTP uses STARTTLS with a *verified* context and refuses to send credentials
  over an unencrypted connection.  ``starttls()`` without a context encrypts
  but authenticates nothing: any machine in the path could present any
  certificate and read the SMTP password.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from abc import ABC, abstractmethod
from collections.abc import Mapping
from email.message import EmailMessage
from typing import Any

import httpx

from ironflow.config.models import NotificationSpec
from ironflow.config.settings import Settings, get_settings
from ironflow.core.errors import ConfigurationError
from ironflow.core.events import Event, EventBus, EventType
from ironflow.security.guards import NetworkPolicy, validate_url
from ironflow.security.masking import redact_mapping
from ironflow.security.net import build_client
from ironflow.security.secrets import SecretResolver

logger = logging.getLogger(__name__)

#: Which events map to which ``on:`` selector in the pipeline definition.
_EVENT_TRIGGERS: dict[EventType, str] = {
    EventType.PIPELINE_STARTED: "started",
    EventType.PIPELINE_SUCCEEDED: "success",
    EventType.PIPELINE_FAILED: "failed",
    EventType.PIPELINE_CANCELLED: "failed",
}


class Notifier(ABC):
    """Base class for notification channels."""

    name: str = "notifier"
    #: Hosts a channel may post to when the pipeline names none.
    default_hosts: tuple[str, ...] = ()

    def __init__(self, spec: NotificationSpec, settings: Settings | None = None) -> None:
        self.spec = spec
        self.settings = settings or get_settings()
        self.secrets = SecretResolver.for_pipelines(self.settings)

    @abstractmethod
    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool:
        """Deliver a notification.  Returns success; never raises."""
        raise NotImplementedError

    def option(self, key: str, default: Any = None) -> Any:
        return self.spec.options.get(key, default)

    def target(self) -> str:
        if not self.spec.target:
            raise ConfigurationError(f"notification channel {self.spec.type!r} requires a 'target'")
        resolved = self.secrets.reveal(self.spec.target, name=f"notification.{self.spec.type}")
        return str(resolved)

    def network_policy(self) -> NetworkPolicy:
        """The operator's policy, narrowed to the channel's allowed hosts."""
        hosts = self.option("allowed_hosts") or list(self.default_hosts) or None
        return NetworkPolicy.from_settings(self.settings).narrowed(allowed_hosts=hosts)

    def http_client(self) -> httpx.Client:
        """A client that re-checks every connection against the policy."""
        return build_client(
            self.network_policy(),
            verify=self.settings.http_verify_tls,
            timeout=self.settings.http_timeout,
        )

    def post(self, url: str, document: Any, headers: Mapping[str, str] | None = None) -> int:
        """POST ``document`` and return the status without reading the body.

        The endpoint is chosen by a pipeline file and answers with whatever it
        likes; nothing here needs the response, so none of it is read.
        """
        with (
            self.http_client() as client,
            client.stream("POST", url, json=document, headers=dict(headers or {})) as response,
        ):
            return response.status_code


class ConsoleNotifier(Notifier):
    """Write the notification to the log - the default in local development."""

    name = "console"

    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool:
        logger.info("NOTIFICATION | %s | %s", subject, body)
        return True


class WebhookNotifier(Notifier):
    """POST a JSON document to an arbitrary endpoint."""

    name = "webhook"

    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool:
        try:
            url = validate_url(self.target(), policy=self.network_policy())
        except Exception:
            logger.error("webhook target rejected by the URL policy", exc_info=True)
            return False

        document = {
            "subject": subject,
            "message": body,
            "service": self.settings.service_name,
            "environment": self.settings.environment,
            **redact_mapping(payload),
        }
        try:
            status = self.post(
                url,
                document,
                headers={str(k): str(v) for k, v in (self.option("headers") or {}).items()},
            )
        except Exception:
            logger.error("webhook notification failed", exc_info=True)
            return False

        if status >= 400:
            logger.error("webhook returned HTTP %d", status)
            return False
        return True


class SlackNotifier(Notifier):
    """Post a Slack message via an incoming webhook."""

    name = "slack"
    default_hosts = ("hooks.slack.com",)

    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool:
        try:
            url = validate_url(self.target(), policy=self.network_policy())
        except Exception:
            logger.error("slack webhook rejected by the URL policy", exc_info=True)
            return False

        status = str(payload.get("status", "")).lower()
        emoji = {"success": ":white_check_mark:", "partial": ":warning:"}.get(status, ":x:")
        document = {
            "text": f"{emoji} *{subject}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"{emoji} *{subject}*\n{body}"},
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"env: `{self.settings.environment}` • "
                                f"run: `{payload.get('execution_id', '-')}`"
                            ),
                        }
                    ],
                },
            ],
        }
        try:
            http_status = self.post(url, document)
        except Exception:
            logger.error("slack notification failed", exc_info=True)
            return False
        return http_status < 400


class EmailNotifier(Notifier):
    """Send an email over SMTP with STARTTLS.

    Options: ``host``, ``port``, ``user``, ``password``, ``from``, ``use_tls``.
    """

    name = "email"

    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool:
        host = str(self.option("host", "localhost"))
        port = int(self.option("port", 587))
        use_tls = bool(self.option("use_tls", True))
        username = self.secrets.reveal(self.option("user"), name="email.user")
        password = self.secrets.reveal(self.option("password"), name="email.password")
        sender = str(self.option("from", f"ironflow@{host}"))
        recipients = [r.strip() for r in self.target().split(",") if r.strip()]

        if username and not use_tls:
            logger.error("refusing to send SMTP credentials over an unencrypted connection")
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message.set_content(
            f"{body}\n\n---\n{json.dumps(redact_mapping(payload), indent=2, default=str)}"
        )

        try:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                if use_tls:
                    # The system trust store rather than certifi's: a relay
                    # inside a company network is usually signed by a CA the
                    # operator installed on the host, not a public one.
                    smtp.starttls(context=ssl.create_default_context())
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
        except Exception:
            logger.error("email notification failed", exc_info=True)
            return False
        return True


_CHANNELS: dict[str, type[Notifier]] = {
    "console": ConsoleNotifier,
    "webhook": WebhookNotifier,
    "slack": SlackNotifier,
    "email": EmailNotifier,
}


def build_notifier(spec: NotificationSpec, settings: Settings | None = None) -> Notifier:
    channel = _CHANNELS.get(spec.type)
    if channel is None:
        raise ConfigurationError(
            "unsupported notification channel",
            context={"type": spec.type, "supported": sorted(_CHANNELS)},
        )
    return channel(spec, settings)


class NotificationService:
    """Subscribes to the event bus and fans events out to the channels."""

    def __init__(self, specs: list[NotificationSpec], settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._channels: list[tuple[NotificationSpec, Notifier]] = []
        for spec in specs:
            if not spec.enabled:
                continue
            try:
                self._channels.append((spec, build_notifier(spec, self.settings)))
            except ConfigurationError:
                logger.error("skipping invalid notification channel", exc_info=True)
        self._unsubscribe: list[Any] = []

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    def attach(self, bus: EventBus) -> None:
        """Subscribe to pipeline lifecycle events."""
        for event_type in _EVENT_TRIGGERS:
            self._unsubscribe.append(bus.subscribe(event_type, self._handle))

    def detach(self) -> None:
        for unsubscribe in self._unsubscribe:
            unsubscribe()
        self._unsubscribe.clear()

    def _handle(self, event: Event) -> None:
        trigger = _EVENT_TRIGGERS.get(event.type)
        if trigger is None:
            return
        status = str(event.payload.get("status", "")).lower()
        if status == "partial":
            trigger = "partial"

        subject, body = _render(event, trigger)
        for spec, notifier in self._channels:
            if trigger not in spec.on:
                continue
            try:
                delivered = notifier.notify(subject, body, event.to_dict())
            except Exception:
                logger.error("notifier %r raised", notifier.name, exc_info=True)
                continue
            if not delivered:
                logger.warning("notification via %r was not delivered", notifier.name)


def _render(event: Event, trigger: str) -> tuple[str, str]:
    payload = event.payload
    pipeline = event.pipeline_id
    if trigger == "started":
        return (
            f"Pipeline {pipeline} started",
            f"Execution {event.execution_id} started with {payload.get('tasks', '?')} task(s).",
        )
    if trigger in {"success", "partial"}:
        return (
            f"Pipeline {pipeline} finished: {payload.get('status', 'success')}",
            (
                f"Duration {payload.get('duration', 0)}s • "
                f"{payload.get('rows_written', 0)} row(s) written • "
                f"{payload.get('rows_rejected', 0)} rejected."
            ),
        )
    return (
        f"Pipeline {pipeline} FAILED",
        f"Execution {event.execution_id} failed: {payload.get('error') or 'unknown error'}",
    )


__all__ = [
    "ConsoleNotifier",
    "EmailNotifier",
    "NotificationService",
    "Notifier",
    "SlackNotifier",
    "WebhookNotifier",
    "build_notifier",
]

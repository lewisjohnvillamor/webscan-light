"""Notifications for new findings — webhook and/or email, standard library + requests.

All configuration is via environment variables so nothing sensitive is stored:
  WEBSCAN_WEBHOOK_URL         POST a JSON payload here (Slack/Discord/generic)
  WEBSCAN_SMTP_HOST/PORT      SMTP server (PORT default 587)
  WEBSCAN_SMTP_USER/PASSWORD  SMTP auth (optional)
  WEBSCAN_SMTP_FROM/TO        envelope addresses (TO may be comma-separated)
  WEBSCAN_SMTP_TLS            "1" to STARTTLS (default on when user set)
Every send is best-effort and never raises.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
from email.message import EmailMessage


def channels_configured() -> list[str]:
    active = []
    if os.environ.get("WEBSCAN_WEBHOOK_URL", "").strip():
        active.append("webhook")
    if os.environ.get("WEBSCAN_SMTP_HOST", "").strip() and os.environ.get("WEBSCAN_SMTP_TO", "").strip():
        active.append("email")
    return active


def _send_webhook(subject: str, text: str, payload: dict) -> None:
    url = os.environ.get("WEBSCAN_WEBHOOK_URL", "").strip()
    if not url:
        return
    import requests
    # "text" satisfies Slack/Discord; the structured payload rides alongside.
    body = {"text": f"*{subject}*\n{text}", "webscan": payload}
    try:
        requests.post(url, json=body, timeout=15)
    except requests.RequestException:
        pass


def _send_email(subject: str, text: str) -> None:
    host = os.environ.get("WEBSCAN_SMTP_HOST", "").strip()
    to = os.environ.get("WEBSCAN_SMTP_TO", "").strip()
    if not host or not to:
        return
    port = int(os.environ.get("WEBSCAN_SMTP_PORT", "587") or 587)
    user = os.environ.get("WEBSCAN_SMTP_USER", "").strip()
    password = os.environ.get("WEBSCAN_SMTP_PASSWORD", "")
    sender = os.environ.get("WEBSCAN_SMTP_FROM", user or "webscan@localhost")
    use_tls = os.environ.get("WEBSCAN_SMTP_TLS", "1" if user else "0").lower() in ("1", "true", "yes", "on")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to
    message.set_content(text)
    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            if use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError):
        pass


def notify(subject: str, text: str, payload: dict | None = None) -> None:
    payload = payload or {}
    _send_webhook(subject, text, payload)
    _send_email(subject, text)

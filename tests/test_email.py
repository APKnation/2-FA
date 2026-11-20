
import smtplib

import pyotp

from app.services import auth_service
from app.services import mail

# Make email OTP deterministic in tests.
auth_service._generate_email_otp = lambda: "123456"


def _set_mail_env(monkeypatch, **overrides):
    values = {
        "MAIL_HOST": "smtp.example.com",
        "MAIL_PORT": 587,
        "MAIL_USERNAME": "smtp-user",
        "MAIL_PASSWORD": "smtp-pass",
        "MAIL_FROM": "noreply@secureauth.local",
        "MAIL_USE_TLS": True,
        "MAIL_USE_SSL": False,
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setattr(mail.settings, key, value)


def test_send_verification_code_skipped_without_smtp_config(monkeypatch):
    # With no MAIL_HOST / MAIL_FROM configured the mail is skipped.
    monkeypatch.setattr(mail.settings, "MAIL_HOST", "")
    monkeypatch.setattr(mail.settings, "MAIL_FROM", "")
    assert mail.send_verification_code("user@example.com", "123456") is False


def test_send_verification_code_sends_to_registered_email(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host
            sent["port"] = port
            sent["timeout"] = timeout

        def login(self, username, password):
            sent["login"] = username

        def starttls(self):
            sent["tls"] = True

        def send_message(self, message):
            sent["to"] = message["To"]
            sent["subject"] = message["Subject"]
            sent["body"] = message.get_payload(decode=True).decode()

        def quit(self):
            sent["quit"] = True

    _set_mail_env(monkeypatch)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    assert mail.send_verification_code("user@example.com", "123456", "Alice") is True
    assert sent["host"] == "smtp.example.com"
    assert sent["port"] == 587
    assert sent["to"] == "user@example.com"
    assert "123456" in sent["body"]
    assert sent["login"] == "smtp-user"
    assert sent["tls"] is True


def test_send_verification_code_swallows_smtp_errors(monkeypatch):
    class ExplodingSMTP:
        def __init__(self, *args, **kwargs):
            raise OSError("no route to host")

    _set_mail_env(monkeypatch)
    monkeypatch.setattr(smtplib, "SMTP", ExplodingSMTP)

    assert mail.send_verification_code("user@example.com", "123456") is False


def test_send_verification_code_skips_when_from_missing(monkeypatch):
    _set_mail_env(monkeypatch, MAIL_FROM="")
    assert mail.send_verification_code("user@example.com", "123456") is False


def _enable_2fa(client, email):
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Sup3r-Secret!", "full_name": "Mail User"},
    )
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": "Sup3r-Secret!"})
    challenge = login_resp.json()["challenge_token"]
    token = client.post(
        "/api/v1/auth/verify-2fa", json={"challenge_token": challenge, "code": "123456"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    secret = client.post("/api/v1/auth/2fa/setup", headers=headers).json()["secret"]
    code = pyotp.TOTP(secret).now()
    response = client.post("/api/v1/auth/2fa/confirm", json={"code": code}, headers=headers)
    assert response.status_code == 200


def test_login_challenge_includes_email_code_sent_flag(client, monkeypatch):
    _enable_2fa(client, "mailuser@example.com")
    monkeypatch.setattr(
        auth_service.mail, "send_verification_code", lambda email, code, full_name=None: False
    )

    body = client.post("/api/v1/auth/login", json={"email": "mailuser@example.com", "password": "Sup3r-Secret!"}).json()
    assert body["requires_2fa"] is True
    assert body["email_code_sent"] is False


def test_login_challenge_reports_email_code_sent(client, monkeypatch):
    _enable_2fa(client, "mailuser2@example.com")
    monkeypatch.setattr(
        auth_service.mail, "send_verification_code", lambda email, code, full_name=None: True
    )

    body = client.post("/api/v1/auth/login", json={"email": "mailuser2@example.com", "password": "Sup3r-Secret!"}).json()
    assert body["requires_2fa"] is True
    assert body["email_code_sent"] is True

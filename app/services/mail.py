
"""SMTP helper used to send the 2FA verification code to the registered email."""

import logging
import smtplib
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_verification_code(email: str, code: str, full_name: str | None = None) -> bool:
    """Email a TOTP verification code to ``email``.

    Returns True when the mail was sent successfully. Without SMTP settings the
    mail is skipped and False is returned, so the flow still works with an
    authenticator app alone.
    """
    if not settings.MAIL_HOST or not settings.MAIL_FROM:
        return False

    name = f" {full_name}," if full_name else ","
    body = f"""Hello{name}

You started signing in with two-factor authentication for your SecureAuth account.

Verification code: {code}

The code expires in 30 seconds. If you did not start this sign-in, ignore this email.

Regards,
SecureAuth
"""

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = "Your SecureAuth verification code"
    message["From"] = settings.MAIL_FROM
    message["To"] = email

    smtp = None
    try:
        if settings.MAIL_USE_SSL:
            smtp = smtplib.SMTP_SSL(settings.MAIL_HOST, settings.MAIL_PORT, timeout=10)
        else:
            smtp = smtplib.SMTP(settings.MAIL_HOST, settings.MAIL_PORT, timeout=10)
        if settings.MAIL_USE_TLS and not settings.MAIL_USE_SSL:
            smtp.starttls()
        if settings.MAIL_USERNAME and settings.MAIL_PASSWORD:
            smtp.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)
        smtp.send_message(message)
        return True
    except Exception as exc:  # noqa: BLE001 — never break sign-in on mail failure
        logger.warning("Failed to send 2FA verification code to %s: %s", email, exc)
        return False
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:  # noqa: BLE001
                pass

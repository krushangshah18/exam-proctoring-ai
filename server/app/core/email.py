import smtplib
from email.message import EmailMessage

from app.core import settings, log


def send_email(to: str, subject: str, body: str):
    """
    Generic email sender.
    Used for reset password, alerts, notifications.
    """

    msg = EmailMessage()
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject

    msg.set_content(body)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:

            if settings.SMTP_TLS:
                server.starttls()

            server.login(
                settings.SMTP_USER,
                settings.SMTP_PASSWORD
            )

            server.send_message(msg)

        log.info(f"Email sent to {to}")

    except Exception as e:
        log.exception(f"Email sending failed {e}")
        raise

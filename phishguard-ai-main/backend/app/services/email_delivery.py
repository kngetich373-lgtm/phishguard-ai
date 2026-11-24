import asyncio
import smtplib
from email.message import EmailMessage

from fastapi import HTTPException

from app.config import get_settings


settings = get_settings()


def send_account_email(recipient: str, subject: str, body: str) -> None:
    if not settings.smtp_host or not settings.smtp_from_email:
        raise HTTPException(
            status_code=503,
            detail="Account email delivery is not configured",
        )

    message = EmailMessage()
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.ehlo()
        if settings.smtp_use_tls:
            smtp.starttls()
            smtp.ehlo()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


async def deliver_account_email(recipient: str, subject: str, body: str) -> None:
    await asyncio.to_thread(send_account_email, recipient, subject, body)

"""Email alert dispatch via SMTP."""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from specter.models.alert import MonitoringAlert

logger = logging.getLogger(__name__)


class EmailDispatch:
    """Sends MonitoringAlerts via SMTP."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_addr: str,
        recipients: list[str],
        use_tls: bool = True,
    ) -> None:
        self._host = smtp_host
        self._port = smtp_port
        self._user = username
        self._password = password
        self._from = from_addr
        self._recipients = recipients
        self._tls = use_tls

    async def send(self, alert: MonitoringAlert) -> bool:
        """Format and send the alert email. Returns True on success."""
        try:
            msg = self._format(alert)
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                if self._tls:
                    server.starttls()
                server.login(self._user, self._password)
                server.send_message(msg)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Email dispatch failed: %s", exc)
            return False

    def _format(self, alert: MonitoringAlert) -> MIMEMultipart:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Specter] {alert.severity.upper()}: {alert.title}"
        msg["From"] = self._from
        msg["To"] = ", ".join(self._recipients)

        findings_html = "".join(f"<li>{f}</li>" for f in alert.findings)
        html_body = f"""
        <html><body>
          <h2 style='color: {'red' if alert.severity in ('high','critical') else 'orange'};'>
            {alert.title}
          </h2>
          <p><strong>Severity:</strong> {alert.severity.upper()}</p>
          <p><strong>Target:</strong> {alert.target_id}</p>
          <p><strong>Summary:</strong> {alert.summary}</p>
          {'<ul>' + findings_html + '</ul>' if findings_html else ''}
          <hr><small>Specter Protective Intelligence Platform</small>
        </body></html>
        """
        text_body = (
            f"Specter Alert [{alert.severity.upper()}]\n"
            f"{alert.title}\n\n"
            f"Target: {alert.target_id}\n"
            f"Summary: {alert.summary}\n"
            + ("\nFindings:\n" + "\n".join(f"  - {f}" for f in alert.findings)
               if alert.findings else "")
        )
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))
        return msg

"""
Alert Forwarder: Sends alert JSON to the SOC backend via REST API.

Handles:
- HTTPS POST with retry logic
- API key authentication
- Batch sending for efficiency
- Error handling and logging
"""

import logging
import os
from typing import List, Dict, Any

import httpx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()


class AlertForwarder:
    """
    Forwards enriched alerts to the SOC backend API.
    """

    def __init__(
        self,
        backend_url: str = None,
        api_key: str = None,
        timeout: float = 10.0,
        max_retries: int = 3,
    ):
        self.backend_url = backend_url or os.getenv("SOC_BACKEND_URL", "http://localhost:8000/api/v1")
        self.api_key = api_key or os.getenv("INGESTION_API_KEY", "dev-api-key")
        self.timeout = timeout
        self.max_retries = max_retries

        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
        }

        logger.info(f"Alert forwarder initialized: {self.backend_url}")

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Send a single alert to the SOC backend.

        Args:
            alert: Alert dict (as produced by DetectionPipeline).

        Returns:
            True if successfully sent, False otherwise.
        """
        url = f"{self.backend_url}/alerts"

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, json=alert, headers=self.headers)

                if response.status_code in (200, 201):
                    logger.debug(f"Alert {alert['alert_id']} sent successfully")
                    return True
                else:
                    logger.warning(
                        f"Alert send failed (attempt {attempt}/{self.max_retries}): "
                        f"HTTP {response.status_code} - {response.text[:200]}"
                    )
            except httpx.ConnectError:
                logger.warning(
                    f"Connection failed (attempt {attempt}/{self.max_retries}): "
                    f"SOC backend not reachable at {url}"
                )
            except Exception as e:
                logger.error(f"Alert send error (attempt {attempt}/{self.max_retries}): {e}")

        logger.error(f"Alert {alert['alert_id']} failed after {self.max_retries} attempts")
        return False

    def send_batch(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Send a batch of alerts to the SOC backend.

        Args:
            alerts: List of alert dicts.

        Returns:
            Dict with 'sent' and 'failed' counts.
        """
        sent = 0
        failed = 0

        for alert in alerts:
            if self.send_alert(alert):
                sent += 1
            else:
                failed += 1

        logger.info(f"Batch complete: {sent} sent, {failed} failed out of {len(alerts)}")
        return {"sent": sent, "failed": failed}

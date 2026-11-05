"""AWS CloudTrail log ingestion."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class AWSIngest(BaseIngest):
    """AWS CloudTrail log ingestion adapter."""

    def connect(self) -> bool:
        try:
            access_key = self.config.get("access_key_id")
            secret_key = self.config.get("secret_access_key")
            region = self.config.get("region", "us-east-1")

            if access_key and secret_key:
                self.client = boto3.client(
                    "cloudtrail",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region,
                )
            else:
                self.client = boto3.client("cloudtrail", region_name=region)

            self._connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to AWS: {e}")
            return False

    def disconnect(self) -> None:
        self._connected = False
        self.client = None

    def ingest(self, start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[TelemetryEvent]:
        if not self.is_connected():
            return []

        events = []
        try:
            kwargs = {"LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": "*"}]}
            if start_time:
                kwargs["StartTime"] = start_time
            if end_time:
                kwargs["EndTime"] = end_time

            response = self.client.lookup_events(**kwargs)

            for event in response.get("Events", []):
                events.append(
                    TelemetryEvent(
                        source="aws_cloudtrail",
                        event_type=event.get("EventName"),
                        timestamp=event.get("EventTime"),
                        data={
                            "event_id": event.get("EventId"),
                            "event_source": event.get("EventSource"),
                            "user_identity": event.get("UserIdentity"),
                            "resources": event.get("Resources"),
                            "request_parameters": event.get("RequestParameters"),
                        },
                        raw=json.dumps(event),
                    )
                )
        except ClientError as e:
            logger.error(f"AWS API error: {e}")
        except Exception as e:
            logger.error(f"Failed to ingest AWS logs: {e}")

        return events

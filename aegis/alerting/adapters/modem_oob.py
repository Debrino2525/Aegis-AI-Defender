"""
Aegis AI — Out-Of-Band (OOB) Cellular Serial Modem Adapter.
Communicates directly with an on-premises USB/Serial 4G LTE modem using standard
Hayes AT commands (AT+CMGS) for completely air-gapped critical emergency dispatch.
"""

import os
import time
from typing import Optional
from dotenv import load_dotenv
from aegis.alerting.models import CriticalAlert, OnCallContact, DispatchResult, ChannelType
from aegis.alerting.adapters.base import BaseAlertAdapter
from aegis.alerting.security import sanitize_for_public_channel

load_dotenv()


class ModemOOBAdapter(BaseAlertAdapter):
    """
    Direct hardware serial modem adapter for air-gapped out-of-band delivery.
    Operates independently of local ISP, DNS, or Ethernet infrastructure.
    """

    def __init__(self):
        self.port = os.getenv("MODEM_SERIAL_PORT", "").strip()
        self.baudrate = int(os.getenv("MODEM_BAUDRATE", "115200"))

    @property
    def channel_name(self) -> str:
        return ChannelType.MODEM_OOB.value

    async def send(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> DispatchResult:
        start_time = time.time()
        recipient_phone = contact.phone.strip()
        if not self.port:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.MODEM_OOB,
                success=False,
                recipient=recipient_phone,
                error="No modem serial port configured",
                latency_ms=round(latency, 2)
            )

        # Check if pyserial is available
        try:
            import serial
        except ImportError:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.MODEM_OOB,
                success=False,
                recipient=recipient_phone,
                error="pyserial not installed; physical modem requires 'pip install pyserial'",
                latency_ms=round(latency, 2)
            )

        # Build emergency message
        msg = f"[AEGIS OOB EMERGENCY] {alert.title} in Zone {alert.metadata.get('environment', 'Production')}. Check console."

        try:
            # Attempt to connect to serial port
            with serial.Serial(self.port, self.baudrate, timeout=3.0) as ser:
                ser.write(b"AT\r\n")
                time.sleep(0.3)
                resp = ser.read_all().decode("ascii", errors="ignore")
                if "OK" not in resp:
                    raise IOError(f"Modem did not respond with OK on {self.port}: {resp}")

                # Set Text Mode
                ser.write(b"AT+CMGF=1\r\n")
                time.sleep(0.3)
                
                # Send SMS command
                cmd = f'AT+CMGS="{recipient_phone}"\r\n'.encode("ascii")
                ser.write(cmd)
                time.sleep(0.5)

                # Send body terminated with Ctrl+Z (0x1A)
                ser.write(msg.encode("ascii") + b"\x1A")
                time.sleep(3.0)
                
                modem_resp = ser.read_all().decode("ascii", errors="ignore")
                latency = (time.time() - start_time) * 1000

                if "+CMGS:" in modem_resp or "OK" in modem_resp:
                    return DispatchResult(
                        channel=ChannelType.MODEM_OOB,
                        success=True,
                        recipient=recipient_phone,
                        provider_ref="serial_at_ack",
                        latency_ms=round(latency, 2)
                    )
                else:
                    return DispatchResult(
                        channel=ChannelType.MODEM_OOB,
                        success=False,
                        recipient=recipient_phone,
                        error=f"Modem AT response: {modem_resp[:100]}",
                        latency_ms=round(latency, 2)
                    )
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.MODEM_OOB,
                success=False,
                recipient=recipient_phone,
                error=f"Hardware serial port {self.port} unreachable: {str(e)}",
                latency_ms=round(latency, 2)
            )

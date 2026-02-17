from __future__ import annotations

import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class MtlsConfig:
    cert_path: str
    key_path: str
    ca_bundle: Optional[str] = None

    def cert_pair(self) -> tuple[str, str]:
        return (self.cert_path, self.key_path)


class AuthStrategy:
    def headers(self, body: bytes) -> Dict[str, str]:
        return {}


@dataclass
class HmacAuth(AuthStrategy):
    secret: bytes
    actor: Optional[str] = None

    def headers(self, body: bytes) -> Dict[str, str]:
        timestamp = str(int(time.time()))
        actor_value = self.actor or ""
        message = b".".join(
            [
                timestamp.encode("utf-8"),
                actor_value.encode("utf-8"),
                body,
            ]
        )
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()

        headers = {
            "X-Nucleus-Timestamp": timestamp,
            "X-Nucleus-Signature": signature,
        }
        if actor_value:
            headers["X-Nucleus-Actor"] = actor_value
        return headers

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class PodSpec:
    work_dir: str = "."
    timeout_seconds: int = 3600
    profile: str = "default"
    network_allow: Optional[List[str]] = None
    dns_allow: Optional[List[str]] = None
    cpu_cores: Optional[int] = None
    memory_mib: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        spec: Dict[str, object] = {
            "apiVersion": "nucleus/v1",
            "kind": "Pod",
            "metadata": {},
            "spec": {
                "work_dir": self.work_dir,
                "timeout_seconds": self.timeout_seconds,
                "policy": {"type": "profile", "name": self.profile},
            },
        }

        if self.network_allow or self.dns_allow:
            spec["spec"]["network"] = {
                "allow": self.network_allow or [],
                "dns_allow": self.dns_allow or [],
            }

        if self.cpu_cores is not None or self.memory_mib is not None:
            spec["spec"]["resources"] = {
                "cpu_cores": self.cpu_cores,
                "memory_mib": self.memory_mib,
            }

        return spec

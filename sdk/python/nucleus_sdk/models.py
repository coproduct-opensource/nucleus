from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PodSpec:
    work_dir: str = "."
    timeout_seconds: int = 3600
    profile: str = "default"
    network_allow: Optional[List[str]] = None
    dns_allow: Optional[List[str]] = None
    cpu_cores: Optional[int] = None
    memory_mib: Optional[int] = None
    labels: Optional[Dict[str, str]] = None
    task: Optional[str] = None
    budget_max_usd: Optional[float] = None

    def to_dict(self) -> Dict[str, object]:
        metadata: Dict[str, object] = {}
        if self.labels:
            metadata["labels"] = dict(self.labels)

        inner_spec: Dict[str, object] = {
            "work_dir": self.work_dir,
            "timeout_seconds": self.timeout_seconds,
            "policy": {"type": "profile", "name": self.profile},
        }

        if self.task is not None:
            inner_spec["task"] = self.task

        if self.budget_max_usd is not None:
            inner_spec["budget"] = {"max_usd": self.budget_max_usd}

        if self.network_allow or self.dns_allow:
            inner_spec["network"] = {
                "allow": self.network_allow or [],
                "dns_allow": self.dns_allow or [],
            }

        if self.cpu_cores is not None or self.memory_mib is not None:
            inner_spec["resources"] = {
                "cpu_cores": self.cpu_cores,
                "memory_mib": self.memory_mib,
            }

        spec: Dict[str, object] = {
            "apiVersion": "nucleus/v1",
            "kind": "Pod",
            "metadata": metadata,
            "spec": inner_spec,
        }

        return spec


@dataclass
class PodInfo:
    """Information about a managed pod."""

    id: str
    created_at_unix: int
    state: str
    name: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None
    proxy_addr: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PodInfo:
        # nucleus-node uses externally-tagged serde for state:
        # "running" | {"exited": {"code": N}} | {"error": {"message": "..."}}
        raw_state = d.get("state", "unknown")
        state: str
        exit_code: Optional[int] = None
        error: Optional[str] = None

        if isinstance(raw_state, str):
            state = raw_state
        elif isinstance(raw_state, dict):
            if "exited" in raw_state:
                state = "exited"
                exit_code = raw_state["exited"].get("code")
            elif "error" in raw_state:
                state = "error"
                error = raw_state["error"].get("message")
            else:
                state = str(raw_state)
        else:
            state = str(raw_state)

        return cls(
            id=d["id"],
            name=d.get("name"),
            created_at_unix=d.get("created_at_unix", 0),
            state=state,
            exit_code=exit_code,
            error=error,
            proxy_addr=d.get("proxy_addr"),
        )

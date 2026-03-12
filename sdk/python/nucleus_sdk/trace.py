from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class TraceEntry:
    """A single recorded operation in a session trace."""

    timestamp: float
    operation: str
    args: Dict[str, Any]
    result_summary: str
    duration_ms: float
    policy_decision: str  # "allow" or "deny"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)


class Trace:
    """Collects TraceEntry records for a session and exports them."""

    def __init__(self) -> None:
        self._entries: List[TraceEntry] = []

    @property
    def entries(self) -> List[TraceEntry]:
        return list(self._entries)

    def record(
        self,
        operation: str,
        args: Dict[str, Any],
        result_summary: str,
        duration_ms: float,
        policy_decision: str = "allow",
    ) -> TraceEntry:
        entry = TraceEntry(
            timestamp=time.time(),
            operation=operation,
            args=args,
            result_summary=result_summary,
            duration_ms=duration_ms,
            policy_decision=policy_decision,
        )
        self._entries.append(entry)
        return entry

    def export_dict(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._entries]

    def export_jsonl(self) -> str:
        return "\n".join(e.to_json() for e in self._entries)

    def __len__(self) -> int:
        return len(self._entries)

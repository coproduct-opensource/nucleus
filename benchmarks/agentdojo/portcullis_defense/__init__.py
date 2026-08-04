"""Portcullis defense adapter for the AgentDojo benchmark.

The exposure-lattice reimplementation that used to live here has been removed —
see `defense._MIRROR_REMOVED` for why and for the measured divergence. What
remains is the AgentDojo pipeline scaffolding and `tool_map`, which is
benchmark-domain knowledge rather than duplicated policy: the mapping from
AgentDojo's fine-grained tools onto nucleus's coarse operations is a judgment
call that determines the results, so it belongs in the open next to them.

Enforcement decisions belong to the kernel. Drive them through the
`nucleus-flow-replay` crate, which calls the same decision function the live
HTTP chokepoint calls.

`PortcullisDefense` is intentionally NOT re-exported here: importing this
package must not look like a working defense is available.
"""

from .tool_map import TOOL_MAP, ExposureLabel

__all__ = [
    "TOOL_MAP",
    "ExposureLabel",
]

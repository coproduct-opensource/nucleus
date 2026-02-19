from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from .models import PodSpec
from .client import ProxyClient


class Intent(str, Enum):
    RESEARCH_WEB = "research_web"
    CODE_REVIEW = "code_review"
    FIX_ISSUE = "fix_issue"
    GENERATE_CODE = "generate_code"
    RELEASE = "release"
    DATABASE_CLIENT = "database_client"
    READ_ONLY = "read_only"
    EDIT_ONLY = "edit_only"
    LOCAL_DEV = "local_dev"
    NETWORK_ONLY = "network_only"
    ORCHESTRATE = "orchestrate"


@dataclass(frozen=True)
class IntentProfile:
    intent: Intent
    profile: str
    description: str
    allowed_ops: List[str]
    gated_ops: List[str]
    notes: Optional[str] = None


INTENT_PROFILES: Dict[Intent, IntentProfile] = {
    Intent.RESEARCH_WEB: IntentProfile(
        intent=Intent.RESEARCH_WEB,
        profile="web_research",
        description="Read files plus web search/fetch.",
        allowed_ops=["read", "glob", "grep", "web_search", "web_fetch"],
        gated_ops=[],
    ),
    Intent.CODE_REVIEW: IntentProfile(
        intent=Intent.CODE_REVIEW,
        profile="code_review",
        description="Read-only repo review with optional web lookup.",
        allowed_ops=["read", "glob", "grep", "web_search"],
        gated_ops=[],
    ),
    Intent.FIX_ISSUE: IntentProfile(
        intent=Intent.FIX_ISSUE,
        profile="fix_issue",
        description="Edit + run tools; approvals required when trifecta is active.",
        allowed_ops=["read", "write", "run", "glob", "grep"],
        gated_ops=["run", "web_fetch", "web_search", "git_push"],
        notes="Exfiltration vectors may require approval when trifecta is complete.",
    ),
    Intent.GENERATE_CODE: IntentProfile(
        intent=Intent.GENERATE_CODE,
        profile="codegen",
        description="Write + run tools without network.",
        allowed_ops=["read", "write", "run", "glob", "grep"],
        gated_ops=[],
    ),
    Intent.RELEASE: IntentProfile(
        intent=Intent.RELEASE,
        profile="release",
        description="Release flow with explicit approvals.",
        allowed_ops=["read", "write", "run", "web_search", "web_fetch"],
        gated_ops=["git_push", "create_pr", "run"],
    ),
    Intent.DATABASE_CLIENT: IntentProfile(
        intent=Intent.DATABASE_CLIENT,
        profile="database_client",
        description="Database CLI only.",
        allowed_ops=["run"],
        gated_ops=[],
    ),
    Intent.READ_ONLY: IntentProfile(
        intent=Intent.READ_ONLY,
        profile="read_only",
        description="Explore files safely; no writes or execution.",
        allowed_ops=["read", "glob", "grep"],
        gated_ops=[],
    ),
    Intent.EDIT_ONLY: IntentProfile(
        intent=Intent.EDIT_ONLY,
        profile="edit_only",
        description="Edit files without execution or network.",
        allowed_ops=["read", "write", "glob", "grep"],
        gated_ops=[],
    ),
    Intent.LOCAL_DEV: IntentProfile(
        intent=Intent.LOCAL_DEV,
        profile="local_dev",
        description="Local development without network.",
        allowed_ops=["read", "write", "run", "glob", "grep"],
        gated_ops=[],
    ),
    Intent.NETWORK_ONLY: IntentProfile(
        intent=Intent.NETWORK_ONLY,
        profile="network_only",
        description="Web-only research with no file access.",
        allowed_ops=["web_search", "web_fetch"],
        gated_ops=[],
    ),
    Intent.ORCHESTRATE: IntentProfile(
        intent=Intent.ORCHESTRATE,
        profile="orchestrator",
        description="Spawn and manage sub-pods. No direct file/command/web access.",
        allowed_ops=["read", "glob", "grep", "create_pod", "list_pods", "pod_status", "pod_logs", "cancel_pod"],
        gated_ops=[],
        notes="Sub-pod permissions bounded by delegation ceiling via monotonic meet.",
    ),
}


class IntentSession:
    def __init__(self, proxy: ProxyClient, profile: IntentProfile, pod_id: Optional[str] = None):
        self._proxy = proxy
        self.profile = profile
        self.pod_id = pod_id

    def describe(self) -> IntentProfile:
        return self.profile

    def read(self, path: str) -> str:
        return self._proxy.read(path)

    def write(self, path: str, contents: str) -> None:
        self._proxy.write(path, contents)

    def run(self, args: List[str], stdin: Optional[str] = None, directory: Optional[str] = None):
        return self._proxy.run(args=args, stdin=stdin, directory=directory)

    def web_fetch(self, url: str, method: Optional[str] = None, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None):
        return self._proxy.web_fetch(url=url, method=method, headers=headers, body=body)

    def web_search(self, query: str, max_results: Optional[int] = None):
        return self._proxy.web_search(query=query, max_results=max_results)

    def glob(self, pattern: str, directory: Optional[str] = None, max_results: Optional[int] = None):
        return self._proxy.glob(pattern=pattern, directory=directory, max_results=max_results)

    def grep(self, pattern: str, path: Optional[str] = None, file_glob: Optional[str] = None, context_lines: Optional[int] = None, max_matches: Optional[int] = None, case_insensitive: Optional[bool] = None):
        return self._proxy.grep(
            pattern=pattern,
            path=path,
            file_glob=file_glob,
            context_lines=context_lines,
            max_matches=max_matches,
            case_insensitive=case_insensitive,
        )


def profile_for_intent(intent: Intent) -> IntentProfile:
    return INTENT_PROFILES[intent]


def pod_spec_for_intent(intent: Intent, work_dir: str = ".", timeout_seconds: int = 3600) -> PodSpec:
    profile = profile_for_intent(intent)
    return PodSpec(work_dir=work_dir, timeout_seconds=timeout_seconds, profile=profile.profile)

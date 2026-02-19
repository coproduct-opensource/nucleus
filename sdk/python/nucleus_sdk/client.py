from __future__ import annotations

import json
from typing import Any, Dict, Optional

import requests

from .auth import AuthStrategy, MtlsConfig
from .errors import NucleusError, RequestError, from_error_payload
from .models import PodSpec


class BaseClient:
    def __init__(
        self,
        base_url: str,
        auth: Optional[AuthStrategy] = None,
        mtls: Optional[MtlsConfig] = None,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.timeout = timeout
        self.session = requests.Session()

        if mtls is not None:
            self.session.cert = mtls.cert_pair()
            if mtls.ca_bundle:
                self.session.verify = mtls.ca_bundle
            else:
                self.session.verify = True

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}

        body_bytes = b""
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            body_bytes = body.encode("utf-8")
        if self.auth is not None:
            headers.update(self.auth.headers(body_bytes))

        response = self.session.request(
            method,
            url,
            data=body_bytes if payload is not None else None,
            headers=headers,
            timeout=self.timeout,
        )

        if response.status_code >= 400:
            try:
                error_payload = response.json()
            except ValueError:
                raise RequestError(
                    f"request failed ({response.status_code})",
                    status=response.status_code,
                )
            raise from_error_payload(error_payload, response.status_code)

        if response.content:
            return response.json()
        return {}


class ProxyClient(BaseClient):
    def read(self, path: str) -> str:
        payload = {"path": path}
        data = self._request("POST", "/v1/read", payload)
        return data.get("contents", "")

    def write(self, path: str, contents: str) -> None:
        payload = {"path": path, "contents": contents}
        self._request("POST", "/v1/write", payload)

    def run(
        self,
        args: list[str],
        stdin: Optional[str] = None,
        directory: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"args": args}
        if stdin is not None:
            payload["stdin"] = stdin
        if directory is not None:
            payload["directory"] = directory
        return self._request("POST", "/v1/run", payload)

    def web_fetch(
        self,
        url: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"url": url}
        if method is not None:
            payload["method"] = method
        if headers is not None:
            payload["headers"] = headers
        if body is not None:
            payload["body"] = body
        return self._request("POST", "/v1/web_fetch", payload)

    def web_search(self, query: str, max_results: Optional[int] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"query": query}
        if max_results is not None:
            payload["max_results"] = max_results
        return self._request("POST", "/v1/web_search", payload)

    def glob(
        self,
        pattern: str,
        directory: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"pattern": pattern}
        if directory is not None:
            payload["directory"] = directory
        if max_results is not None:
            payload["max_results"] = max_results
        return self._request("POST", "/v1/glob", payload)

    def grep(
        self,
        pattern: str,
        path: Optional[str] = None,
        file_glob: Optional[str] = None,
        context_lines: Optional[int] = None,
        max_matches: Optional[int] = None,
        case_insensitive: Optional[bool] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"pattern": pattern}
        if path is not None:
            payload["path"] = path
        if file_glob is not None:
            payload["glob"] = file_glob
        if context_lines is not None:
            payload["context_lines"] = context_lines
        if max_matches is not None:
            payload["max_matches"] = max_matches
        if case_insensitive is not None:
            payload["case_insensitive"] = case_insensitive
        return self._request("POST", "/v1/grep", payload)

    def approve(self, operation: str, count: int = 1, expires_at_unix: Optional[int] = None, nonce: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"operation": operation, "count": count}
        if expires_at_unix is not None:
            payload["expires_at_unix"] = expires_at_unix
        if nonce is not None:
            payload["nonce"] = nonce
        return self._request("POST", "/v1/approve", payload)

    def create_pod(self, spec_yaml: str, reason: str) -> Dict[str, Any]:
        """Create a sub-pod. Only available in orchestrator mode."""
        return self._request("POST", "/v1/pod/create", {"spec_yaml": spec_yaml, "reason": reason})

    def list_pods(self) -> Dict[str, Any]:
        """List managed sub-pods."""
        return self._request("POST", "/v1/pod/list", {})

    def pod_status(self, pod_id: str) -> Dict[str, Any]:
        """Get sub-pod status."""
        return self._request("POST", "/v1/pod/status", {"pod_id": pod_id})

    def pod_logs(self, pod_id: str) -> Dict[str, Any]:
        """Get sub-pod logs."""
        return self._request("POST", "/v1/pod/logs", {"pod_id": pod_id})

    def cancel_pod(self, pod_id: str, reason: str = "") -> Dict[str, Any]:
        """Cancel a running sub-pod."""
        return self._request("POST", "/v1/pod/cancel", {"pod_id": pod_id, "reason": reason})


class NodeClient(BaseClient):
    def create_pod(self, spec: PodSpec) -> Dict[str, Any]:
        payload = {"spec": spec.to_dict()}
        return self._request("POST", "/v1/pods", payload)

    def list_pods(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/pods")

    def pod_logs(self, pod_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/pods/{pod_id}/logs")

    def cancel_pod(self, pod_id: str) -> Dict[str, Any]:
        return self._request("POST", f"/v1/pods/{pod_id}/cancel")


class Nucleus:
    def __init__(
        self,
        proxy_url: Optional[str] = None,
        node_url: Optional[str] = None,
        auth: Optional[AuthStrategy] = None,
        mtls: Optional[MtlsConfig] = None,
        timeout: float = 30.0,
    ) -> None:
        self.proxy_url = proxy_url
        self.node_url = node_url
        self.auth = auth
        self.mtls = mtls
        self.timeout = timeout

    def proxy(self) -> ProxyClient:
        if not self.proxy_url:
            raise ValueError("proxy_url is required to create a ProxyClient")
        return ProxyClient(self.proxy_url, auth=self.auth, mtls=self.mtls, timeout=self.timeout)

    def node(self) -> NodeClient:
        if not self.node_url:
            raise ValueError("node_url is required to create a NodeClient")
        return NodeClient(self.node_url, auth=self.auth, mtls=self.mtls, timeout=self.timeout)

    def proxy_at(self, url: str) -> ProxyClient:
        """Create a ProxyClient pointing at a specific tool-proxy address."""
        return ProxyClient(url, auth=self.auth, mtls=self.mtls, timeout=self.timeout)

    def intent(self, intent, work_dir: str = ".", timeout_seconds: int = 3600):
        from .intent import Intent, IntentSession, profile_for_intent, pod_spec_for_intent

        if not isinstance(intent, Intent):
            raise ValueError("intent must be an Intent enum")

        profile = profile_for_intent(intent)

        if self.proxy_url:
            proxy_client = self.proxy()
            return IntentSession(proxy_client, profile)

        if not self.node_url:
            raise ValueError("proxy_url or node_url is required to open an intent")

        node_client = self.node()
        pod_spec = pod_spec_for_intent(intent, work_dir=work_dir, timeout_seconds=timeout_seconds)
        result = node_client.create_pod(pod_spec)
        proxy_addr = result.get("proxy_addr")
        if not proxy_addr:
            raise NucleusError("pod created but proxy address missing")

        proxy_client = ProxyClient(proxy_addr, auth=self.auth, mtls=self.mtls, timeout=self.timeout)
        return IntentSession(proxy_client, profile, pod_id=str(result.get("id")))

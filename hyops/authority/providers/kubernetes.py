"""Kubernetes resource binding for the operation authority contract."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request

from ..models import (
    AuthorityContext,
    AuthorityDeclaration,
    AuthorityEvaluation,
    AuthorityIntervalEvaluation,
    AuthorityObservation,
    AuthorityObservationPolicy,
)
from ._common import (
    config_bool,
    config_positive_number,
    endpoint_identity,
    open_no_redirect,
    require_known_config,
)


_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_RESOURCE_VERSION_RE = re.compile(r"^[1-9][0-9]*$")


class KubernetesAuthorityProvider:
    name = "kubernetes"
    capabilities = frozenset({"resource_authority"})
    _CONFIG_KEYS = {
        "endpoint",
        "endpoint_env",
        "instance_id",
        "resource_path",
        "timeout_s",
        "token_env",
        "verify_tls",
    }

    def validate_configuration(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
    ) -> None:
        del context
        config = declaration.config
        require_known_config(config, self._CONFIG_KEYS)
        config_bool(config, "verify_tls", True)
        config_positive_number(config, "timeout_s", 5.0)
        for key, default in (
            ("endpoint_env", "KUBERNETES_API_URL"),
            ("token_env", "KUBERNETES_API_TOKEN"),
        ):
            value = str(config.get(key) or default).strip()
            if not _ENV_NAME_RE.fullmatch(value):
                raise ValueError(f"config.{key} must name an uppercase environment variable")
        endpoint = str(config.get("endpoint") or "").strip()
        if endpoint:
            _api_endpoint(endpoint)
        _resource_path(config)
        instance_id = config.get("instance_id")
        if instance_id is not None and not str(instance_id).strip():
            raise ValueError("config.instance_id must be a non-empty string")

    def evaluate(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
    ) -> AuthorityEvaluation:
        config = declaration.config
        endpoint_env = str(config.get("endpoint_env") or "KUBERNETES_API_URL").strip()
        token_env = str(config.get("token_env") or "KUBERNETES_API_TOKEN").strip()
        raw_endpoint = str(config.get("endpoint") or context.env.get(endpoint_env) or "").strip()
        token = str(context.env.get(token_env) or "").strip()
        missing = []
        if not raw_endpoint:
            missing.append(endpoint_env)
        if not token:
            missing.append(token_env)
        if missing:
            raise ValueError(
                f"missing required Kubernetes configuration: {', '.join(missing)}"
            )

        endpoint = _api_endpoint(raw_endpoint)
        resource_path = _resource_path(config)
        resource_url = f"{endpoint}{resource_path}"
        error, resource, observed_at = _read_resource(
            resource_url,
            token=token,
            timeout_s=float(config_positive_number(config, "timeout_s", 5.0) or 5.0),
            verify_tls=config_bool(config, "verify_tls", True),
        )
        instance = str(config.get("instance_id") or endpoint_identity(endpoint))
        if error:
            return AuthorityEvaluation(
                healthy=False,
                state="unhealthy",
                result=error,
                instance=instance,
                endpoint=endpoint_identity(endpoint),
                freshness={"checked_at": observed_at} if observed_at else {},
            )

        metadata = resource.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("Kubernetes resource metadata is missing")
        name = _required_text(metadata.get("name"), "metadata.name")
        expected_name = unquote(resource_path.rsplit("/", 1)[-1])
        if name != expected_name:
            raise ValueError(
                "Kubernetes resource metadata.name does not match config.resource_path"
            )
        uid = _required_text(metadata.get("uid"), "metadata.uid")
        resource_version = _required_text(
            metadata.get("resourceVersion"),
            "metadata.resourceVersion",
        )
        api_version = _required_text(resource.get("apiVersion"), "apiVersion")
        kind = _required_text(resource.get("kind"), "kind")

        return AuthorityEvaluation(
            healthy=True,
            state="ready",
            result="authoritative resource observed",
            instance=instance,
            endpoint=endpoint_identity(endpoint),
            revision=resource_version,
            freshness={"checked_at": observed_at, "source": "fresh API GET"},
            observation=AuthorityObservation(
                token=f"resourceVersion:{resource_version}",
                observed_at=observed_at,
                scope=resource_url,
                strength="kubernetes-resource-version",
                metadata={
                    "api_version": api_version,
                    "kind": kind,
                    "name": name,
                    "uid": uid,
                },
            ),
        )

    def interval_verifiable(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
        before: AuthorityObservation,
        policy: AuthorityObservationPolicy,
    ) -> bool:
        del declaration, context
        return (
            policy.expected_change == "none"
            and before.strength == "kubernetes-resource-version"
            and bool(_observation_uid(before))
            and bool(_resource_version(before))
        )

    def evaluate_interval(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
        before: AuthorityObservation,
        after: AuthorityObservation,
        policy: AuthorityObservationPolicy,
        completion_floor: str,
    ) -> AuthorityIntervalEvaluation:
        del declaration, context, completion_floor
        if policy.expected_change != "none":
            return AuthorityIntervalEvaluation(
                interval_status="unverifiable",
                completion_status="fresh",
                result="resourceVersion cannot attribute an expected operation write",
                detection_strength="kubernetes-resource-version",
                freshness_basis="fresh Kubernetes API GET",
            )

        before_uid = _observation_uid(before)
        after_uid = _observation_uid(after)
        before_version = _resource_version(before)
        after_version = _resource_version(after)
        if not before_uid or not after_uid or not before_version or not after_version:
            raise ValueError("Kubernetes authority observation is incomplete")
        if before_uid != after_uid:
            return _drifted("Kubernetes authority object was replaced")

        ordering = _compare_resource_versions(before_version, after_version)
        if ordering is not None and ordering > 0:
            return AuthorityIntervalEvaluation(
                interval_status="unverifiable",
                completion_status="stale",
                result="completion resourceVersion predates the admission revision",
                detection_strength="kubernetes-resource-version",
                freshness_basis="fresh Kubernetes API GET",
            )
        if before_version != after_version:
            return _drifted("Kubernetes authority resource changed during the operation")
        return AuthorityIntervalEvaluation(
            interval_status="stable",
            completion_status="fresh",
            result="Kubernetes authority resource remained unchanged",
            detection_strength="kubernetes-resource-version",
            freshness_basis="fresh Kubernetes API GET",
        )


def _api_endpoint(raw: str) -> str:
    token = str(raw or "").strip().rstrip("/")
    parsed = urlsplit(token)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Kubernetes endpoint must be an http(s) URL")
    if parsed.scheme == "http" and not _loopback_host(parsed.hostname):
        raise ValueError(
            "Kubernetes endpoint must use https; plain http is allowed only for loopback"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "Kubernetes endpoint must not contain credentials, query parameters, or fragments"
        )
    if parsed.path not in {"", "/"}:
        raise ValueError("Kubernetes endpoint must not contain a path")
    return f"{parsed.scheme}://{parsed.netloc}"


def _loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _resource_path(config: Mapping[str, Any]) -> str:
    raw = str(config.get("resource_path") or "").strip()
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("config.resource_path must be an absolute Kubernetes API path")
    path = parsed.path.rstrip("/")
    parts = [part for part in path.split("/") if part]
    core_resource = (
        len(parts) == 4
        or (len(parts) == 6 and parts[2] == "namespaces")
    ) if parts[:1] == ["api"] else False
    grouped_resource = (
        len(parts) == 5
        or (len(parts) == 7 and parts[3] == "namespaces")
    ) if parts[:1] == ["apis"] else False
    if (
        not (core_resource or grouped_resource)
        or any(part in {".", ".."} for part in parts)
    ):
        raise ValueError("config.resource_path must identify one Kubernetes API resource")
    return path


def _read_resource(
    url: str,
    *,
    token: str,
    timeout_s: float,
    verify_tls: bool,
) -> tuple[str, dict[str, Any], str]:
    request = Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with open_no_redirect(
            request,
            timeout_s=timeout_s,
            verify_tls=verify_tls,
        ) as response:
            code = int(getattr(response, "status", 0) or 0)
            if not 200 <= code < 300:
                return f"Kubernetes API returned HTTP {code}", {}, _utc_text()
            raw_body = response.read(1_048_577)
            observed_at = _utc_text()
            if len(raw_body) > 1_048_576:
                return "Kubernetes API response exceeded 1 MiB", {}, observed_at
            try:
                payload = json.loads(raw_body)
            except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                return "Kubernetes API returned invalid JSON", {}, observed_at
            if not isinstance(payload, dict):
                return "Kubernetes API returned an unexpected response shape", {}, observed_at
            return "", payload, observed_at
    except HTTPError as exc:
        code = int(getattr(exc, "code", 0) or 0)
        if code in (401, 403):
            return f"Kubernetes API rejected the configured token (HTTP {code})", {}, _utc_text()
        if code == 404:
            return "Kubernetes authority resource was not found", {}, _utc_text()
        return f"Kubernetes API returned HTTP {code}", {}, _utc_text()
    except URLError as exc:
        reason = str(getattr(exc, "reason", "") or "").strip() or "connection failed"
        return f"Kubernetes API is unreachable ({reason})", {}, _utc_text()
    except Exception:
        return "Kubernetes API read failed", {}, _utc_text()


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Kubernetes resource {field} is missing")
    return value.strip()


def _observation_uid(observation: AuthorityObservation) -> str:
    return str(observation.metadata.get("uid") or "").strip()


def _resource_version(observation: AuthorityObservation) -> str:
    prefix = "resourceVersion:"
    return observation.token[len(prefix) :] if observation.token.startswith(prefix) else ""


def _compare_resource_versions(before: str, after: str) -> int | None:
    if not _RESOURCE_VERSION_RE.fullmatch(before) or not _RESOURCE_VERSION_RE.fullmatch(after):
        return None
    if len(before) != len(after):
        return -1 if len(before) < len(after) else 1
    return (before > after) - (before < after)


def _drifted(result: str) -> AuthorityIntervalEvaluation:
    return AuthorityIntervalEvaluation(
        interval_status="drifted",
        completion_status="fresh",
        result=result,
        detection_strength="kubernetes-resource-version",
        freshness_basis="fresh Kubernetes API GET",
    )


def _utc_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )

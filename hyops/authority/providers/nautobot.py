"""Nautobot binding for the operation authority contract."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
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
    normalized_base_url,
    open_no_redirect,
    require_known_config,
    utc_text,
)


_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class NautobotAuthorityProvider:
    name = "nautobot"
    capabilities = frozenset({"inventory_ipam"})
    _CONFIG_KEYS = {
        "api_version",
        "endpoint",
        "endpoint_env",
        "instance_id",
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
            ("endpoint_env", "NAUTOBOT_API_URL"),
            ("token_env", "NAUTOBOT_API_TOKEN"),
        ):
            value = str(config.get(key) or default).strip()
            if not _ENV_NAME_RE.fullmatch(value):
                raise ValueError(f"config.{key} must name an uppercase environment variable")
        endpoint = str(config.get("endpoint") or "").strip()
        if endpoint:
            normalized_base_url(endpoint, product="Nautobot")
        instance_id = config.get("instance_id")
        if instance_id is not None and not str(instance_id).strip():
            raise ValueError("config.instance_id must be a non-empty string")
        api_version = config.get("api_version")
        if api_version is not None and not re.fullmatch(r"[0-9]+\.[0-9]+", str(api_version)):
            raise ValueError("config.api_version must use major.minor format")

    def evaluate(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
    ) -> AuthorityEvaluation:
        config = declaration.config
        endpoint_env = str(config.get("endpoint_env") or "NAUTOBOT_API_URL").strip()
        token_env = str(config.get("token_env") or "NAUTOBOT_API_TOKEN").strip()
        raw_endpoint = str(config.get("endpoint") or context.env.get(endpoint_env) or "").strip()
        token = str(context.env.get(token_env) or "").strip()
        missing = []
        if not raw_endpoint:
            missing.append(endpoint_env)
        if not token:
            missing.append(token_env)
        if missing:
            raise ValueError(f"missing required Nautobot configuration: {', '.join(missing)}")

        base_url = normalized_base_url(raw_endpoint, product="Nautobot")
        safe_endpoint = endpoint_identity(base_url)
        instance = str(config.get("instance_id") or safe_endpoint)
        timeout_s = float(config_positive_number(config, "timeout_s", 5.0) or 5.0)
        verify_tls = config_bool(config, "verify_tls", True)

        health_error, _, _ = _probe(
            f"{base_url.rstrip('/')}/health/",
            headers={"Accept": "text/html"},
            timeout_s=timeout_s,
            verify_tls=verify_tls,
            product="Nautobot health endpoint",
        )
        if health_error:
            return AuthorityEvaluation(
                healthy=False,
                state="unhealthy",
                result=health_error,
                instance=instance,
                endpoint=safe_endpoint,
                freshness={"checked_at": utc_text()},
            )

        accept = "application/json"
        api_version = str(config.get("api_version") or "").strip()
        if api_version:
            accept += f"; version={api_version}"
        observation_url = f"{base_url.rstrip('/')}/api/ipam/prefixes/?limit=1"
        api_error, headers, response_digest = _probe(
            observation_url,
            headers={"Authorization": f"Token {token}", "Accept": accept},
            timeout_s=timeout_s,
            verify_tls=verify_tls,
            product="Nautobot IPAM API",
            expect_paginated_json=True,
        )
        if api_error:
            return AuthorityEvaluation(
                healthy=False,
                state="unhealthy",
                result=api_error,
                instance=instance,
                endpoint=safe_endpoint,
                freshness={"checked_at": utc_text()},
            )

        revision = str(headers.get("API-Version") or headers.get("api-version") or api_version)
        return AuthorityEvaluation(
            healthy=True,
            state="ready",
            result="admitted",
            instance=instance,
            endpoint=safe_endpoint,
            revision=revision,
            freshness={"checked_at": utc_text(), "source": "live"},
            observation=AuthorityObservation(
                token=f"sha256:{response_digest}",
                observed_at=datetime.now(timezone.utc).isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
                scope=observation_url,
                strength="snapshot",
                metadata={"source": "authenticated live API read"},
            ),
        )

    def interval_verifiable(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
        before: AuthorityObservation,
        policy: AuthorityObservationPolicy,
    ) -> bool:
        del declaration, context, before, policy
        return False

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
        if policy.expected_change == "none" and before.token != after.token:
            return AuthorityIntervalEvaluation(
                interval_status="drifted",
                completion_status="fresh",
                result="authority snapshot changed during a no-change interval",
                detection_strength="snapshot",
                freshness_basis="authenticated live API read",
            )
        return AuthorityIntervalEvaluation(
            interval_status="unverifiable",
            completion_status="fresh",
            result="fresh authority snapshot observed; interval history unavailable",
            detection_strength="snapshot",
            freshness_basis="authenticated live API read",
        )


def _probe(
    url: str,
    *,
    headers: dict[str, str],
    timeout_s: float,
    verify_tls: bool,
    product: str,
    expect_paginated_json: bool = False,
) -> tuple[str, dict[str, str], str]:
    request = Request(url, headers=headers, method="GET")
    try:
        with open_no_redirect(
            request,
            timeout_s=timeout_s,
            verify_tls=verify_tls,
        ) as response:
            code = int(getattr(response, "status", 0) or 0)
            response_headers = dict(getattr(response, "headers", {}) or {})
            if not 200 <= code < 300:
                return f"{product} returned HTTP {code}", response_headers, ""
            response_digest = ""
            if expect_paginated_json:
                raw_body = response.read(1_048_577)
                if len(raw_body) > 1_048_576:
                    return f"{product} response exceeded 1 MiB", response_headers, ""
                try:
                    payload = json.loads(raw_body)
                except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                    return f"{product} returned an invalid JSON response", response_headers, ""
                if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                    return f"{product} returned an unexpected response shape", response_headers, ""
                canonical = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                response_digest = hashlib.sha256(canonical).hexdigest()
            return "", response_headers, response_digest
    except HTTPError as exc:
        code = int(getattr(exc, "code", 0) or 0)
        if code in (401, 403):
            return f"{product} rejected the configured API token (HTTP {code})", {}, ""
        return f"{product} returned HTTP {code}", {}, ""
    except URLError as exc:
        reason = str(getattr(exc, "reason", "") or "").strip() or "connection failed"
        return f"{product} is unreachable ({reason})", {}, ""
    except Exception:
        return f"{product} probe failed", {}, ""

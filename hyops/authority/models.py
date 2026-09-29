"""Typed values shared by authority providers and their resolver."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class AuthorityDeclaration:
    """A logical authority bound to a configured provider."""

    logical_ref: str
    capability: str
    provider: str
    config: Mapping[str, Any] = field(default_factory=dict)
    compatibility: bool = False


@dataclass(frozen=True)
class AuthorityRequirement:
    """The logical authority and capability required by one operation."""

    logical_ref: str
    capability: str
    compatibility: bool = False


@dataclass(frozen=True)
class AuthorityObservationPolicy:
    """How one operation treats authority observations across dispatch."""

    expected_change: str
    on_unverifiable: str


@dataclass(frozen=True)
class AuthorityContext:
    """Runtime inputs available to every authority provider."""

    runtime_root: Path
    state_root: Path
    env: Mapping[str, str]
    assumed_state_ok: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AuthorityEvaluation:
    """Secret-free provider evaluation returned to the generic resolver."""

    healthy: bool
    state: str
    result: str
    instance: str = ""
    endpoint: str = ""
    revision: str = ""
    freshness: Mapping[str, Any] = field(default_factory=dict)
    observation: "AuthorityObservation | None" = None


@dataclass(frozen=True)
class AuthorityObservation:
    """Secret-free, provider-produced observation of one authority scope."""

    token: str
    observed_at: str
    scope: str
    strength: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "token": self.token,
            "observed_at": self.observed_at,
            "scope": self.scope,
            "strength": self.strength,
        }
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass(frozen=True)
class AuthorityIntervalEvaluation:
    """Provider verdict for the governed interval and completion read."""

    interval_status: str
    completion_status: str
    result: str
    detection_strength: str
    freshness_basis: str


@dataclass(frozen=True)
class AuthorityIntervalReceipt:
    """Runtime decision and evidence for authority continuity across dispatch."""

    logical_ref: str
    capability: str
    provider: str
    expected_change: str
    on_unverifiable: str
    interval_status: str
    completion_status: str
    decision: str
    result: str
    detection_strength: str
    freshness_basis: str
    before: AuthorityObservation | None = None
    after: AuthorityObservation | None = None

    def to_evidence(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "logical_authority": self.logical_ref,
            "capability": self.capability,
            "provider": self.provider,
            "expected_change": self.expected_change,
            "on_unverifiable": self.on_unverifiable,
            "interval_status": self.interval_status,
            "completion_status": self.completion_status,
            "decision": self.decision,
            "result": self.result,
            "detection_strength": self.detection_strength,
            "freshness_basis": self.freshness_basis,
        }
        if self.before is not None:
            payload["before"] = self.before.to_evidence()
        if self.after is not None:
            payload["after"] = self.after.to_evidence()
        return payload


@dataclass(frozen=True)
class AuthorityReceipt:
    """Attributable evidence that an operation authority was admitted."""

    logical_ref: str
    capability: str
    provider: str
    state: str
    result: str
    instance: str = ""
    endpoint: str = ""
    revision: str = ""
    freshness: Mapping[str, Any] = field(default_factory=dict)
    observation: AuthorityObservation | None = None

    def to_evidence(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "logical_authority": self.logical_ref,
            "capability": self.capability,
            "provider": self.provider,
            "verified_state": self.state,
            "result": self.result,
        }
        if self.instance:
            payload["instance"] = self.instance
        if self.endpoint:
            payload["endpoint"] = self.endpoint
        if self.revision:
            payload["revision"] = self.revision
        if self.freshness:
            payload["freshness"] = dict(self.freshness)
        if self.observation is not None:
            payload["observation"] = self.observation.to_evidence()
        return payload


@dataclass(frozen=True)
class AuthoritySession:
    """Transient authority binding retained only for one dispatch interval."""

    requirement: AuthorityRequirement
    declaration: AuthorityDeclaration
    context: AuthorityContext
    admission: AuthorityReceipt

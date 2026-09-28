"""Interface implemented by shipped authority providers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    AuthorityContext,
    AuthorityDeclaration,
    AuthorityEvaluation,
    AuthorityIntervalEvaluation,
    AuthorityObservation,
    AuthorityObservationPolicy,
)


class AuthorityProvider(Protocol):
    name: str
    capabilities: frozenset[str]

    def validate_configuration(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
    ) -> None: ...

    def evaluate(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
    ) -> AuthorityEvaluation: ...


@runtime_checkable
class AuthorityIntervalProvider(Protocol):
    """Optional provider capability for interval and completion evaluation.

    ``stable`` requires provider evidence that can exclude intervening drift.
    Completion freshness must come from an authoritative read performed after
    ``completion_floor``, not from event ingestion time.
    """

    def interval_verifiable(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
        before: AuthorityObservation,
        policy: AuthorityObservationPolicy,
    ) -> bool: ...

    def evaluate_interval(
        self,
        declaration: AuthorityDeclaration,
        context: AuthorityContext,
        before: AuthorityObservation,
        after: AuthorityObservation,
        policy: AuthorityObservationPolicy,
        completion_floor: str,
    ) -> AuthorityIntervalEvaluation: ...

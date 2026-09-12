"""Pure severity and correlation logic.

Nothing here reads a database or a broker. Correlation is deterministic on
purpose: an analyst must be able to reproduce why these detections became one
incident, months later, during a post-incident review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

SEVERITY_ORDER = ('info', 'low', 'medium', 'high', 'critical')

SEVERITY_SCORE = {'info': 5, 'low': 20, 'medium': 45, 'high': 70, 'critical': 90}

CRITICALITY_MULTIPLIER = {
    'low': 0.8,
    'medium': 1.0,
    'high': 1.2,
    'crown_jewel': 1.5,
}


class CorrelationError(ValueError):
    pass


@dataclass(frozen=True)
class Detection:
    detection_id: str
    rule_code: str
    detected_at: datetime
    severity: str
    host_id: str | None = None
    user_name: str | None = None
    source_ip: str | None = None
    process_guid: str | None = None


@dataclass(frozen=True)
class Incident:
    primary_entity: str
    entity_type: str
    detections: tuple[Detection, ...]
    severity: str
    risk_score: int
    window_start: datetime
    window_end: datetime


def severity_rank(severity: str) -> int:
    if severity not in SEVERITY_ORDER:
        raise CorrelationError(f'unknown severity: {severity}')
    return SEVERITY_ORDER.index(severity)


def max_severity(severities: list[str]) -> str:
    if not severities:
        raise CorrelationError('no severities supplied')
    return max(severities, key=severity_rank)


def adjust_severity(
    base: str,
    asset_criticality: str,
    is_internet_facing: bool = False,
) -> str:
    """Raise severity on important or exposed assets; never lower it below base."""
    rank = severity_rank(base)

    if asset_criticality == 'crown_jewel':
        rank += 2
    elif asset_criticality == 'high':
        rank += 1

    if is_internet_facing:
        rank += 1

    return SEVERITY_ORDER[min(rank, len(SEVERITY_ORDER) - 1)]


def risk_score(
    detections: list[Detection],
    asset_criticality: str = 'medium',
) -> int:
    """Highest detection drives the score; additional distinct rules add evidence.

    Summing severities would let a hundred low alerts outrank one LSASS dump,
    which is the wrong answer, so the base is the maximum, not the sum.
    """
    if not detections:
        raise CorrelationError('cannot score an empty incident')

    if asset_criticality not in CRITICALITY_MULTIPLIER:
        raise CorrelationError(f'unknown criticality: {asset_criticality}')

    base = max(SEVERITY_SCORE[d.severity] for d in detections)
    distinct_rules = len({d.rule_code for d in detections})
    corroboration = min(15, (distinct_rules - 1) * 5)
    score = (
        base + corroboration
    ) * CRITICALITY_MULTIPLIER[asset_criticality]

    return int(min(100, round(score)))


def dedup_key(
    rule_code: str,
    entity: str,
    detected_at: datetime,
    window_minutes: int = 15,
) -> str:
    """Stable across replays: the same rule and entity inside one window collapse."""
    if window_minutes <= 0:
        raise CorrelationError('dedup window must be positive')

    epoch_minutes = int(detected_at.timestamp() // 60)
    bucket = epoch_minutes // window_minutes

    return f'{rule_code}|{entity}|{bucket}'


def primary_entity(detection: Detection) -> tuple[str, str]:
    """Entity precedence: host, then identity, then source address."""
    if detection.host_id:
        return detection.host_id, 'host'

    if detection.user_name:
        return detection.user_name, 'identity'

    if detection.source_ip:
        return detection.source_ip, 'source_ip'

    raise CorrelationError(
        f'detection {detection.detection_id} has no correlatable entity'
    )


@dataclass
class Correlator:
    window: timedelta = field(
        default_factory=lambda: timedelta(minutes=60)
    )
    asset_criticality: dict = field(default_factory=dict)

    def correlate(self, detections: list[Detection]) -> list[Incident]:
        """Group by entity, then split each group on gaps larger than the window."""
        if self.window <= timedelta(0):
            raise CorrelationError('correlation window must be positive')

        buckets: dict[tuple[str, str], list[Detection]] = {}

        for d in detections:
            key = primary_entity(d)
            buckets.setdefault(key, []).append(d)

        incidents: list[Incident] = []

        for (entity, entity_type), group in buckets.items():
            group.sort(key=lambda d: d.detected_at)
            chain: list[Detection] = [group[0]]

            for previous, current in zip(group, group[1:]):
                if current.detected_at - previous.detected_at <= self.window:
                    chain.append(current)
                else:
                    incidents.append(
                        self._build(entity, entity_type, chain)
                    )
                    chain = [current]

            incidents.append(
                self._build(entity, entity_type, chain)
            )

        incidents.sort(key=lambda i: (-i.risk_score, i.window_start))
        return incidents

    def _build(
        self,
        entity: str,
        entity_type: str,
        chain: list[Detection],
    ) -> Incident:
        criticality = self.asset_criticality.get(entity, 'medium')

        return Incident(
            primary_entity=entity,
            entity_type=entity_type,
            detections=tuple(chain),
            severity=adjust_severity(
                max_severity([d.severity for d in chain]),
                criticality,
            ),
            risk_score=risk_score(chain, criticality),
            window_start=chain[0].detected_at,
            window_end=chain[-1].detected_at,
        )
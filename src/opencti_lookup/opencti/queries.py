"""GraphQL documents. Validated against a live OpenCTI 7.260907.0 instance."""

from __future__ import annotations

from typing import Any

#: Resolve an observable by exact value and pull every Indicator linked to it.
#: One round trip. The hit verdict is decided entirely inside `indicators`.
#:
#: 7.x note: objectLabel and objectMarking come back as plain arrays here, not
#: the edges/node wrapping older releases used. `indicators` is still edge-wrapped.
LOOKUP = """
query IndicatorLookup($filters: FilterGroup!, $types: [String]) {
  stixCyberObservables(filters: $filters, types: $types, first: 1) {
    edges { node {
      id
      entity_type
      observable_value
      x_opencti_score
      objectMarking { definition }
      indicators { edges { node {
        id
        name
        pattern_type
        confidence
        x_opencti_score
        x_opencti_detection
        valid_from
        valid_until
        revoked
        description
        objectLabel { value }
        objectMarking { definition }
        createdBy { ... on Identity { name } }
        killChainPhases { phase_name }
      } } }
    } }
  }
}
"""

#: Bootstrap page, fast path: observable values only, no relationship traversal.
#:
#: Measured on a live 7.26 instance, walking indicators and following the
#: nested `observables` edge runs at ~210 values/sec; reading observables
#: directly runs at ~3,500 -- 17x faster (17.7k in 5s rather than 88s, and
#: 1M in ~5min rather than ~80min). The nested traversal is the whole cost.
#:
#: Trading precision for that is safe because the membership set is only a
#: pre-filter: an observable carrying no indicator produces a false "present",
#: which triggers a payload query, which returns a miss, which is cached. On
#: an instance where observables and indicators are near 1:1 the false
#: positive rate is negligible; where observables greatly outnumber
#: indicators, MEMBERSHIP_SOURCE=indicators forces the precise path below.
BOOTSTRAP_OBSERVABLES = """
query BootstrapObservables($first: Int!, $after: ID) {
  stixCyberObservables(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage globalCount }
    edges { node { observable_value } } }
}
"""

#: Bootstrap page, precise path: only values that genuinely carry an indicator.
BOOTSTRAP_INDICATORS = """
query BootstrapIndicators($first: Int!, $after: ID) {
  indicators(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage globalCount }
    edges { node {
      id
      observables { edges { node { observable_value } } }
    } }
  }
}
"""

COUNT_INDICATORS = """
query CountIndicators { indicators { pageInfo { globalCount } } }
"""

COUNT_OBSERVABLES = """
query CountObservables { stixCyberObservables { pageInfo { globalCount } } }
"""

HEALTH = """
query Health { about { version } }
"""


def value_filter(value: str) -> dict[str, Any]:
    """Exact match on the indexed `value` field of an observable."""
    return {
        "mode": "and",
        "filterGroups": [],
        "filters": [
            {"key": "value", "operator": "eq", "values": [value], "mode": "or"}
        ],
    }

"""
Phone-number reputation subsystem (the live, transcript-free path of the hybrid
CallKit→VishGuard contract — see docs/CALLKIT_DATA_CONTRACT.md).

CallKit hands us a *caller ID*, not a transcript. The reputation aggregator scores
that number against many external feeds (FTC, Nomorobo, Hiya, Truecaller,
Robokiller, …) plus our own observed-threat history, behind ONE vendor-agnostic
interface. Each provider is:

  - env-keyed  : disabled automatically when its API key is absent (no key → skip)
  - fail-safe  : a provider error/timeout never breaks screening (returns None)
  - cacheable  : results are Redis-cached (TTL) so we don't re-bill a vendor per call

Public surface:
    from common.reputation import score_number, get_aggregator
"""
from common.reputation.base import (
    ReputationScore,
    ReputationProvider,
    Verdict,
)
from common.reputation.aggregator import (
    ReputationAggregator,
    get_aggregator,
    score_number,
)

__all__ = [
    "ReputationScore",
    "ReputationProvider",
    "ReputationAggregator",
    "Verdict",
    "get_aggregator",
    "score_number",
]

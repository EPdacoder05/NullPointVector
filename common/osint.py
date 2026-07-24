"""
Pro-tier identity enrichment — thin orchestrator over outsourced vendors.

See common/vendors/identity.py for the real integrations:
  Plaid (KYC / bank identity) + Array/credit partner (scores) + IPQS (breach).
"""
from __future__ import annotations

from typing import Any, Optional

from common.vendors.identity import (
    VendorReport,
    breach_exposure,
    credit_score_lookup,
    enrich_identity_bundle,
    plaid_identity_get,
    plaid_identity_status,
)

# Backward-compatible aliases
OsintReport = VendorReport
dark_web_exposure = breach_exposure
credit_signal_check = credit_score_lookup


def enrich_identity(
    subject: str,
    *,
    consented: bool = False,
    plaid_access_token: Optional[str] = None,
    credit_user_id: Optional[str] = None,
) -> dict[str, Any]:
    return enrich_identity_bundle(
        subject=subject,
        consented=consented,
        plaid_access_token=plaid_access_token,
        credit_user_id=credit_user_id,
    )


__all__ = [
    "OsintReport",
    "VendorReport",
    "breach_exposure",
    "credit_score_lookup",
    "credit_signal_check",
    "dark_web_exposure",
    "enrich_identity",
    "enrich_identity_bundle",
    "plaid_identity_get",
    "plaid_identity_status",
]

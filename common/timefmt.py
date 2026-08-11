"""UTC → display timezone helpers for Signal Deck timestamps."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# IANA zones for the picker — labels include live abbrev (EDT/PDT/…).
_ZONE_ORDER = [
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Phoenix",
    "America/Anchorage",
    "Pacific/Honolulu",
    "Europe/London",
    "Europe/Paris",
]


def parse_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def resolve_zone(name: Optional[str]) -> ZoneInfo:
    raw = (name or "UTC").strip() or "UTC"
    # Tolerate pasted labels like "America/New_York (EDT)"
    if " " in raw:
        raw = raw.split()[0]
    try:
        return ZoneInfo(raw)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def tz_abbrev(tz_name: Optional[str] = None, when: Optional[datetime] = None) -> str:
    z = resolve_zone(tz_name)
    now = when.astimezone(z) if when else datetime.now(z)
    return now.tzname() or (tz_name or "UTC")


def common_timezone_choices() -> List[Tuple[str, str]]:
    """[(iana, label with current abbrev), ...] for the sidebar picker."""
    out = []
    for z in _ZONE_ORDER:
        abbr = tz_abbrev(z)
        if z == "UTC":
            out.append((z, "UTC"))
        else:
            out.append((z, f"{z} ({abbr})"))
    return out


# Back-compat for templates that iterate string list
COMMON_TIMEZONES = _ZONE_ORDER


def clock_fmt(*, hour12: bool = False, with_seconds: bool = False, with_date: bool = True) -> str:
    """strftime pattern for operator clock preference (12h vs 24h)."""
    if hour12:
        t = "%I:%M:%S %p" if with_seconds else "%I:%M %p"
    else:
        t = "%H:%M:%S" if with_seconds else "%H:%M"
    return f"%Y-%m-%d {t}" if with_date else t


def format_local(
    value,
    tz_name: Optional[str] = None,
    *,
    fmt: Optional[str] = None,
    hour12: bool = False,
    with_seconds: bool = False,
    with_date: bool = True,
    with_tz: bool = True,
) -> str:
    """Render a UTC timestamp in the operator's timezone (+ EDT/PDT when with_tz)."""
    dt = parse_utc(value)
    if not dt:
        return "—"
    local = dt.astimezone(resolve_zone(tz_name))
    pattern = fmt or clock_fmt(hour12=hour12, with_seconds=with_seconds, with_date=with_date)
    out = local.strftime(pattern)
    if hour12:
        # Strip leading zero on the hour ("04:32 PM" → "4:32 PM")
        if with_date and " " in out:
            date_part, rest = out.split(" ", 1)
            if rest.startswith("0") and len(rest) > 1 and rest[1].isdigit():
                out = f"{date_part} {rest[1:]}"
        elif out.startswith("0") and len(out) > 1 and out[1].isdigit():
            out = out[1:]
    if with_tz:
        abbr = local.tzname() or ""
        if abbr and not out.endswith(abbr):
            out = f"{out} {abbr}"
    return out

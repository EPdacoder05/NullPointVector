"""Email Date parse + timezone display."""
from datetime import datetime, timezone
from common.email_time import parse_email_date
from common.timefmt import format_local, common_timezone_choices


def test_parse_rfc2822_to_utc():
    # 4:32 PM EDT = 20:32 UTC
    dt = parse_email_date("Mon, 10 Aug 2026 16:32:00 -0400")
    assert dt.tzinfo is not None
    assert dt.astimezone(timezone.utc).hour == 20
    assert dt.astimezone(timezone.utc).minute == 32


def test_format_local_edt():
    # 20:32 UTC → 4:32 PM EDT
    utc = datetime(2026, 8, 10, 20, 32, tzinfo=timezone.utc)
    out = format_local(utc, "America/New_York", hour12=True, with_date=True)
    assert "4:32 PM" in out or "04:32 PM" in out
    assert "EDT" in out or "EST" in out


def test_tz_picker_labels_have_abbrev():
    choices = common_timezone_choices()
    ny = [c for c in choices if c[0] == "America/New_York"][0]
    assert "America/New_York" in ny[1]
    assert "(" in ny[1]

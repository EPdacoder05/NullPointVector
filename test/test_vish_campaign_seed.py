"""Phone extract + campaign pack smoke tests."""
from pathlib import Path

from common.vish.phones import extract_e164_numbers


def test_extract_callback_tfns():
    text = (
        "Hi, this is Jenny Keys. Press one or call me at 833-684-5481. "
        "Call me at 866-771-5387 again, 866-771-5387."
    )
    nums = extract_e164_numbers(text, exclude=["+19046788702"])
    assert "+18336845481" in nums
    assert "+18667715387" in nums
    assert "+19046788702" not in nums


def test_tax_campaign_pack_loads():
    pack = Path(__file__).resolve().parents[1] / "data" / "vish_campaigns" / "tax_resolution.json"
    assert pack.is_file()
    import json
    data = json.loads(pack.read_text())
    assert len(data["block"]) >= 20
    from common.reputation.base import normalize_number
    for raw in data["block"]:
        n = normalize_number(raw)
        assert n and n.startswith("+")

from common.imap_folders import ingest_lane_for


def test_ingest_lanes_isolate_provider_junk():
    assert ingest_lane_for("INBOX") == "inbox"
    assert ingest_lane_for("Bulk Mail") == "junk"
    assert ingest_lane_for("[Gmail]/Spam") == "junk"
    assert ingest_lane_for("Phishy bizz") == "sandbox"
    assert ingest_lane_for("Phishy_Bizz") == "sandbox"

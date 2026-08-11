"""Category + mood / sentiment tags + recruit/job overrides."""
from common.message_tags import categorize_message
from common.recruit_scam import predict_override
from common.marketing_mail import predict_override as marketing_override


def test_recruiter_gmail_mood():
    tags = categorize_message(
        subject="ACTIVE TWIC CARD REQUIRED",
        body="Hello All You applied to this role",
        sender="Vandana <khemsara@gmail.com>",
    )
    codes = {t["code"] for t in tags}
    assert "RECRUIT_GMAIL" in codes
    assert "SENT_NEG" in codes or "FEAR_URGENCY" in codes or "BLAST" in codes


def test_nsfw_mood():
    tags = categorize_message(
        subject="hey",
        body="lonely tonight want nude pics date me",
        sender="x@evil.example",
    )
    assert any(t["code"] == "RELATIONSHIP_NSFW" for t in tags)


def test_khemsara_override():
    out = predict_override({
        "from": "v khemsara <khemsara@gmail.com>",
        "subject": "ACTIVE TWIC CARD REQUIRED",
        "body": "Hello All, You applied to this role, pls respond if you have an active TWIC card.",
    })
    assert out is not None
    assert out[0] == 1 and out[1] >= 0.85


def test_linkedin_no_override():
    out = predict_override({
        "from": "Praveen Rao <inmail-hit-reply@linkedin.com>",
        "subject": "opportunity",
        "body": "You applied to a role on LinkedIn",
    })
    assert out is None


def test_talentemail_merge_tag_job():
    out = predict_override({
        "from": "Mrinalini Singh <mrinalini.singh@talentemail.com>",
        "subject": "New Job Opportunity, Cloud performance Engineer",
        "body": (
            "Position: Cloud Performance Engineer Job ID Number: 26-09095 Duration: 6 months "
            "please send your resume to [[CANDIDATEEMAIL]] "
            "For reference, your address on file is . If any of your contact details have changed "
            "Please call me at (408) 412-7016 www.talentstaffingservices.com"
        ),
    })
    assert out is not None
    assert out[0] == 1 and out[1] >= 0.9


def test_tldr_marketing_dampen():
    out = marketing_override({
        "from": "TLDR Design <dan@tldrnewsletter.com>",
        "subject": "iPhone Ultra Colors, Adobe ChatGPT Plugin",
        "body": "A new leak suggests Apple's first foldable. Unsubscribe | View in browser",
        "headers": {
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
            "List-Unsubscribe": "<mailto:unsub@tldrnewsletter.com>",
        },
    })
    assert out is not None
    assert out[0] == 0 and out[1] <= 0.2


def test_spam_vs_malice_tags():
    spam = categorize_message(
        subject="Weekly deals",
        body="Shop now 20% off. Unsubscribe here. Newsletter for epinaman@yahoo.com",
        sender="hello@mail.shop.example",
    )
    codes = {t["code"] for t in spam}
    assert "SPAM_LIST" in codes or "THREAT_SPAM" in codes
    assert "MALICE_MONEY" not in codes

    malice = categorize_message(
        subject="Wire needed",
        body="Please send a wire transfer and gift card codes today",
        sender="ceo@evil.example",
    )
    mcodes = {t["code"] for t in malice}
    assert "MALICE_MONEY" in mcodes
    assert "THREAT_MALICE" in mcodes

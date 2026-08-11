"""Policy pipeline + recruit/marketing overrides."""
from common.policy_pipeline import extract_signals, decide_override
from common.recruit_scam import predict_override as recruit_override
from common.message_tags import categorize_message


def test_talentemail_malice_first():
    email = {
        "from": "Mrinalini <mrinalini.singh@talentemail.com>",
        "subject": "Cloud performance Engineer",
        "body": (
            "Position: Cloud Job ID: 26 Duration: 6 months "
            "resume to [[CANDIDATEEMAIL]] address on file is . "
            "call me at (408) 412-7016 www.talentstaffingservices.com"
        ),
        "headers": {"Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"},
    }
    sig = extract_signals(email)
    assert sig["recruit_scam"] is True
    out = decide_override(email)
    assert out and out[0] == 1 and out[1] >= 0.9


def test_tldr_marketing_not_malice():
    email = {
        "from": "TLDR <dan@tldrnewsletter.com>",
        "subject": "OpenAI news",
        "body": "Industry update. Unsubscribe | View in browser newsletter",
        "headers": {
            "Authentication-Results": "mx; spf=pass; dkim=pass header.d=tldrnewsletter.com; dmarc=pass",
            "List-Unsubscribe": "<mailto:u@tldrnewsletter.com>",
        },
    }
    out = decide_override(email)
    assert out and out[0] == 0 and out[1] <= 0.35


def test_known_good_blocked_by_recruit_pattern():
    # Even if somehow on allowlist, merge-tag job scam wins
    email = {
        "from": "x@github.com",
        "subject": "Job",
        "body": "Position: eng Job ID: 1 Duration: 1 send resume [[CANDIDATEEMAIL]] address on file is .",
        "headers": {"Authentication-Results": "mx; dmarc=pass"},
    }
    sig = extract_signals(email)
    assert sig["recruit_scam"]
    out = decide_override(email)
    assert out and out[0] == 1


def test_recruit_module_still_works():
    out = recruit_override({
        "from": "v <khemsara@gmail.com>",
        "subject": "TWIC",
        "body": "Hello All You applied to this role active TWIC card",
    })
    assert out and out[0] == 1


def test_capital_one_auth_financial():
    email = {
        "from": '"Capital One" <capitalone@notification.capitalone.com>',
        "subject": "Your credit score has changed-here's how",
        "body": (
            "Access your newest report to learn more. Sign in to your account. "
            "Help prevent fraud https://click-notification.capitalone.com/f/a/xxx "
            "https://smart.link/abc"
        ),
        "headers": {
            "Authentication-Results": (
                "mx; spf=pass smtp.mailfrom=capitalone.com; "
                "dkim=pass header.d=capitalone.com; dmarc=pass"
            ),
        },
    }
    out = decide_override(email)
    assert out is not None
    assert out[0] == 0 and out[1] <= 0.2


def test_esp_not_bad_url():
    from common.explain import analyze_findings
    findings = analyze_findings(
        "phishing",
        "See https://smart.link/x and https://click-notification.capitalone.com/a",
        '"Capital One" <capitalone@notification.capitalone.com>',
        headers={"Authentication-Results": "mx; dmarc=pass"},
    )
    codes = {f["code"] for f in findings}
    assert "BAD_URL" not in codes

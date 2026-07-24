"""
SmishGuard — SMS smishing detector.

Bootstraps off the PhishGuard architecture via the shared `ChannelDetector`
(word + char TF-IDF + structural features → calibrated SGDClassifier). The only
channel-specific parts are the SMS structural feature vector and the cold-start
corpus below. Detection is a sub-millisecond, single-message latency path —
purpose-built for real-time SMS intercept (no batch email windows).
"""
from __future__ import annotations

import logging
from pathlib import Path

from common.ml import features as F
from common.ml.channel_detector import ChannelDetector

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models" / "smishing_sgd_model.pkl"

# Feature schema version == length of the structural vector. Bump implicitly by
# changing _sms_numeric_features; a mismatch on disk triggers an auto-retrain.
NUM_SMS_FEATURES = 18


def _sms_text(record: dict) -> str:
    """Flatten an SMS record into text for vectorization."""
    body = record.get("body") or record.get("message") or record.get("text") or ""
    sender = record.get("from") or record.get("sender") or record.get("caller_id") or ""
    return f"{sender} {body}".strip()


def _sms_numeric_features(text: str, record: dict | None) -> list:
    """
    18 hard-to-fake structural features for SMS.
    """
    record = record or {}
    body = record.get("body") or record.get("message") or record.get("text") or text
    sender = record.get("from") or record.get("sender") or ""
    length = len(body)
    return [
        float(len(F.urls(body))),
        float(F.shortener_count(body)),
        float(F.suspicious_tld_count(body)),
        float(F.lexicon_count(body, F.URGENCY_WORDS)),
        float(F.lexicon_count(body, F.CREDENTIAL_WORDS)),
        float(F.lexicon_count(body, F.MONEY_WORDS)),
        float(F.lexicon_count(body, F.THREAT_AUTHORITY_WORDS)),
        float(F.has_phone(body)),
        min(length / 160.0, 4.0),           # SMS segments (160 chars each)
        F.non_ascii_ratio(body),
        F.digit_ratio(body),
        F.upper_ratio(body),
        float(body.count("!")),
        float(F.sender_is_shortcode(sender)),
        float(F.sender_is_alpha(sender)),
        float(F.sender_is_long_number(sender)),
        float(F.otp_delivery_signal(body)),
        float(F.otp_theft_signal(body)),
    ]


def _seed_corpus() -> list:
    """Curated cold-start corpus: (record, label) with label 1 = smishing."""
    smish = [
        ("+18885550101", "USPS: your package is on hold due to an unpaid fee. Pay now: http://bit.ly/usps-fee"),
        ("+18005550102", "Your Apple ID has been locked. Verify within 24h or it will be deleted: http://appleid-verify.xyz"),
        ("VERIZON", "URGENT: Your bill is overdue. Avoid suspension, pay immediately: http://vz-billing.click"),
        ("+447700900103", "You have WON a $1000 Walmart gift card! Claim now: http://tinyurl.com/wm-prize"),
        ("+18885550104", "Bank Alert: unusual activity detected. Confirm your identity: http://secure-bank-login.top"),
        ("+12025550105", "IRS Final Notice: you owe back taxes. Pay or face legal action: http://irs-gov-pay.work"),
        ("+18005550106", "Amazon: we couldn't process your order. Update payment: http://amzn-billing.cf"),
        ("+13105550107", "Netflix: your account is on hold. Update billing info: http://netflix-update.ga"),
        ("+18885550108", "Your debit card has been suspended. Reactivate: http://cardservices-verify.tk"),
        ("CHASE", "Chase: did you make a $750 transfer? Reply NO and verify: http://chase-secure.pw"),
        ("+18005550109", "FedEx: address could not be verified. Reschedule delivery: http://fedex-redeliver.bid"),
        ("+12025550110", "Your SSN has been suspended due to suspicious activity. Call immediately to avoid arrest."),
        ("+18885550111", "PayPal: your account is limited. Resolve now to avoid permanent suspension: http://pp-resolve.xyz"),
        ("+13235550112", "Crypto bonus! Deposit $100 get $500. Limited time: http://bit.ly/crypto-x5"),
        ("+18005550113", "Coinbase security: confirm this login or your wallet will be locked: http://cb-verify.click"),
        ("+19175550114", "Mom I dropped my phone in water, this is my new number, text me back I need help with money"),
        ("+18885550115", "Geek Squad renewal $399.99 charged. To cancel call now or pay: http://gs-refund.top"),
        ("+12125550116", "Your account password expires today. Reset now: http://account-reset.loan"),
        ("+18005550117", "Zelle: a $480 payment failed. Verify your bank: http://zelle-verify.men"),
        ("+13105550118", "Toll unpaid: $6.99 outstanding. Pay to avoid penalty: http://ezpass-toll.review"),
        ("+18885550119", "Your DMV registration is suspended. Renew immediately: http://dmv-renew.download"),
        ("+12025550120", "Social Security benefits suspended. Confirm SSN to reinstate: http://ssa-confirm.country"),
        ("+18005550121", "Costco: you've been selected for a reward. Claim your prize: http://costco-reward.win"),
        ("+19295550122", "Bank of America: card locked. Unlock here: http://boa-unlock.cn"),
        ("+18885550123", "Verify your number to keep your account active. Tap: http://acct-keepalive.gq"),
        ("+13475550124", "You have an undelivered voicemail. Listen: http://vm-listen.ru"),
        ("+18005550906", "Hi, this is your bank. Reply with the 6-digit code we sent to confirm it's you."),
    ]
    legit = [
        ("GOOGLE", "Your verification code is 558213. It expires in 10 minutes."),
        ("AMAZON", "123456 is your Amazon OTP. Do not share it with anyone."),
        ("APPLE", "Your Apple ID code is 847291. It expires in 5 minutes."),
        ("CHASE", "Chase: Your one-time passcode is 339102. Never share this code."),
        ("+15551230201", "Hey, running 5 min late — see you at the coffee shop!"),
        ("+15551230202", "Your Uber is arriving now. Toyota Camry, plate 8XYZ123."),
        ("VERIZON", "Your data usage is at 75% of your monthly plan. Manage settings in the My Verizon app."),
        ("+15551230203", "Reminder: dentist appointment tomorrow at 2pm. Reply C to confirm."),
        ("+15551230204", "Mom: don't forget to pick up milk on your way home, love you"),
        ("CHASE", "Chase: your statement is ready. View it securely in the Chase app."),
        ("+15551230205", "Your Amazon package was delivered to your front door."),
        ("+15551230206", "Thanks for your order! It will ship within 2 business days."),
        ("+15551230207", "Pizza Palace: your order #482 is ready for pickup."),
        ("+15551230208", "Hey it's Sarah from work, can you send me the slides when you get a sec?"),
        ("+15551230209", "Your ride with Lyft is complete. Total: $14.20. Rate your driver in the app."),
        ("+15551230210", "Library: the book you reserved is now available for pickup."),
        ("DELTA", "Delta: flight DL482 to ATL is on time, boarding at gate B12 at 3:40pm."),
        ("+15551230211", "Happy birthday! Hope you have an amazing day, let's grab dinner soon"),
        ("+15551230212", "Your appointment with Dr. Lee is confirmed for Thursday 10am."),
        ("+15551230213", "Gym: your class 'Yoga Flow' starts in 1 hour. See you there!"),
        ("STARBUCKS", "You've earned 25 Stars! Check your rewards in the Starbucks app."),
        ("+15551230214", "Hey, the game got moved to Saturday. You still in?"),
        ("+15551230215", "Your grocery delivery window is 5-6pm today. Driver: Mike."),
        ("+15551230216", "Reminder: rent is due on the 1st. Thanks!"),
        ("+15551230217", "It's Dad. Call me when you get a chance, nothing urgent."),
        ("AMC", "AMC: your tickets for the 7:30pm show are confirmed. Enjoy!"),
        ("+15551230218", "Carpool tomorrow at 7:45, I'll swing by your place."),
        ("+15551230219", "Your prescription is ready for pickup at the pharmacy."),
        ("+15551230220", "Team lunch moved to 12:30 in the big conference room."),
        ("+15551230221", "Got the tickets! Can't wait for the concert this weekend."),
    ]
    records = []
    for sender, body in smish:
        records.append(({"from": sender, "body": body}, 1))
    for sender, body in legit:
        records.append(({"from": sender, "body": body}, 0))
    return records


# Process-wide singleton (drop-in `detector` for risk.assess).
detector = ChannelDetector(
    name="SmishGuard",
    model_path=MODEL_PATH,
    text_fn=_sms_text,
    numeric_fn=_sms_numeric_features,
    num_features=NUM_SMS_FEATURES,
    seed_fn=_seed_corpus,
)

# Backwards-compatible class alias for existing imports.
SmishingDetector = ChannelDetector


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    tests = [
        {"from": "+18885550101", "body": "USPS: package on hold, pay fee: http://bit.ly/usps-fee"},
        {"from": "+15551230201", "body": "Hey, running 5 min late — see you at the coffee shop!"},
    ]
    for t in tests:
        pred, conf = detector.predict(t)
        print(f"[{'SMISH' if pred else 'SAFE '}] conf={conf:.2%}  {t['body'][:60]}")

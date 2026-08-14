"""
VishGuard — voice (vishing) detector.

Bootstraps off the PhishGuard architecture via the shared `ChannelDetector`.
Operates on speech-to-text transcripts + caller metadata. The channel-specific
signals are robocall/IVR pressure patterns ("press 1"), authority-impersonation
(IRS/警/arrest scripts), gift-card/wire payment coercion, and caller-ID shape.

This content model runs only when NullPoint legitimately receives text (for
example, an explicitly shared voicemail or an app-owned VoIP transcript). iOS
does not expose carrier-call audio or transcripts to this process, so this model
is not a pre-ring carrier-call hook. Pre-ring carrier protection is driven by
the separate exact-number reputation/directory path.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from common.ml import features as F
from common.ml.channel_detector import ChannelDetector, resolve_model_artifact

logger = logging.getLogger(__name__)

MODEL_PATH = resolve_model_artifact(
    Path(__file__).parent / "models" / "vishing_sgd_model.pkl"
)

NUM_VOICE_FEATURES = 14

_PRESS_RE = re.compile(r"press\s+([0-9]|one|two|three|four|five|six|seven|eight|nine|zero)",
                       re.IGNORECASE)
_AUTOMATED_RE = re.compile(
    r"\b(automated|pre-?recorded|this is a recorded|robot|do not hang up|"
    r"stay on the line|this call may be recorded)\b", re.IGNORECASE)
_CALLBACK_RE = re.compile(
    r"\b(call (us |this number |back )|press \d to speak|to speak (to|with) (an )?agent)\b",
    re.IGNORECASE)
_GIFTCARD_RE = re.compile(
    r"\b(gift ?card|google play|app ?store card|itunes|steam card|"
    r"bitcoin|wire transfer|western union|prepaid card)\b", re.IGNORECASE)


def _voice_text(record: dict) -> str:
    transcript = record.get("transcript") or record.get("body") or record.get("text") or ""
    caller = record.get("caller_id") or record.get("from") or record.get("sender") or ""
    return f"{caller} {transcript}".strip()


def _voice_numeric_features(text: str, record: dict | None) -> list:
    record = record or {}
    transcript = record.get("transcript") or record.get("body") or record.get("text") or text
    caller = record.get("caller_id") or record.get("from") or record.get("sender") or ""
    words = F.tokens(transcript)
    return [
        float(F.lexicon_count(transcript, F.URGENCY_WORDS)),
        float(F.lexicon_count(transcript, F.CREDENTIAL_WORDS)),
        float(F.lexicon_count(transcript, F.MONEY_WORDS)),
        float(F.lexicon_count(transcript, F.THREAT_AUTHORITY_WORDS)),
        float(len(_PRESS_RE.findall(transcript))),
        float(bool(_AUTOMATED_RE.search(transcript))),
        float(bool(_CALLBACK_RE.search(transcript))),
        float(bool(_GIFTCARD_RE.search(transcript))),
        float(F.has_phone(transcript)),
        min(len(transcript) / 200.0, 5.0),
        F.digit_ratio(transcript),
        min(len(words) / 50.0, 5.0),
        float(F.sender_is_alpha(caller)),
        float(F.sender_is_long_number(caller)),
    ]


def _seed_corpus() -> list:
    """Curated cold-start corpus: (record, label) with label 1 = vishing."""
    vish = [
        ("+18005550301", "This is the IRS. A warrant has been issued for your arrest over unpaid taxes. Press 1 to settle immediately or face legal action."),
        ("IRS", "This is an automated call from the Internal Revenue Service. Do not hang up. You owe back taxes. Press 1 to speak with an agent."),
        ("+12025550302", "Your Social Security number has been suspended due to suspicious activity. Press 1 now to avoid arrest."),
        ("+18885550303", "This is Microsoft technical support. Your computer is infected. Allow us remote access and verify your bank account to secure it."),
        ("+18005550304", "We detected fraud on your bank account. To protect your funds, transfer them to a secure account we provide now."),
        ("+13105550305", "Congratulations! You've won a $10,000 prize. To claim, pay the processing fee with a gift card. Read me the card numbers."),
        ("AMAZON", "This is an automated Amazon security call. A $999 charge was made. Press 1 to dispute and confirm your card number."),
        ("+12125550306", "Your electricity will be shut off in 30 minutes for non-payment. Pay immediately with a prepaid card to avoid disconnection."),
        ("+18005550307", "This is your bank's fraud department. Confirm your full card number and PIN so we can stop the unauthorized transaction."),
        ("+19175550308", "We are calling about your car's extended warranty which is about to expire. Press 1 to renew and provide payment now."),
        ("+18885550309", "This is the police department. There is a lawsuit against you. Pay the fine with Western Union immediately or be prosecuted."),
        ("+12025550310", "Immigration services: your visa has issues. Wire the fee now or you will be deported. Do not hang up."),
        ("+13235550311", "Your Apple iCloud has been breached. Read me the verification code we just texted you to secure your account."),
        ("+18005550312", "Automated message: your student loan qualifies for forgiveness. Press 1 and confirm your social security number to enroll."),
        ("+19295550313", "This is Medicare. To keep your benefits active, verify your account number and date of birth now."),
        ("+18885550314", "Final notice from the IRS. Pay your debt with iTunes gift cards within the hour or a warrant will be executed."),
        ("+12125550315", "Your PayPal account shows a suspicious $750 charge. Press 1 to reverse it and confirm your login credentials."),
        ("+13105550316", "This is the utility company. Your bill is overdue. Buy a Google Play card and call us back with the code."),
        ("+18005550317", "Robocall: you have been pre-approved for a loan. Provide your bank routing and account number to receive funds."),
        ("+19175550318", "Grandma, it's me, I'm in jail and need bail money. Please wire it now and don't tell anyone."),
        ("BANK", "Automated alert: card locked. Press 1 and enter your card number and CVV to reactivate immediately."),
        ("+12025550319", "Your Netflix payment failed. Press 1 to update your card details over the phone now."),
        ("+18885550320", "This is the sheriff's office. You missed jury duty. Pay the fine with a gift card to avoid an arrest warrant."),
        ("+13235550321", "Crypto investment opportunity, guaranteed returns. Deposit via bitcoin now before this limited offer expires."),
        ("+18005550322", "Tech support: we found a virus. Stay on the line and give us remote access plus your online banking password."),
        ("+19295550323", "Your account has unauthorized access. Read back the one-time code to verify it's really you and secure it."),
    ]
    legit = [
        ("+15551230401", "Hi, this is Dr. Lee's office confirming your appointment Thursday at 3pm. No action needed, see you then."),
        ("+15551230402", "Hey it's Mike, just calling to see if you're still on for lunch tomorrow. Give me a call back when you can."),
        ("DELTA", "This is a Delta Air Lines courtesy reminder that your flight tomorrow is on time. Check the app for your gate."),
        ("+15551230403", "Hi, this is the pharmacy. Your prescription is ready for pickup any time this week."),
        ("+15551230404", "It's grandma, just calling to say hi and see how the kids are doing. Call me back when you get a minute."),
        ("+15551230405", "This is your dentist's office. We're confirming your cleaning next Monday at 9am. Reply or call to reschedule."),
        ("+15551230406", "Hey, it's Jen from the book club. We moved the meeting to Wednesday, hope you can make it."),
        ("+15551230407", "Hi honey, I'm heading to the store, do we need anything for dinner? Call me back."),
        ("+15551230408", "This is the auto shop, your car is ready for pickup and the total came to about ninety dollars."),
        ("+15551230409", "Hello, this is the school nurse, your child is feeling a bit under the weather but is fine, please call back."),
        ("+15551230410", "Hey it's Tom, the game's on Saturday at noon, you still coming? Let me know."),
        ("+15551230411", "This is your veterinarian's office reminding you that Bella is due for her checkup next week."),
        ("+15551230412", "Hi, calling from the salon to confirm your haircut appointment Friday at 2. See you soon."),
        ("+15551230413", "It's Dad, your mom and I are thinking of visiting next month, call us back to chat about dates."),
        ("+15551230414", "Hello, this is the library, the book you placed on hold is now available for pickup."),
        ("+15551230415", "Hey, it's Carlos from work, do you have the meeting notes from yesterday? No rush."),
        ("+15551230416", "This is your real estate agent, the seller accepted the offer, congratulations, call me to discuss next steps."),
        ("+15551230417", "Hi, this is the catering company confirming the order for Saturday's party. Everything is on track."),
        ("+15551230418", "Hey sis, just checking in, haven't talked in a while. Call me when you're free."),
        ("+15551230419", "This is the plumber, I can come by between 2 and 4 tomorrow to fix the sink, does that work?"),
        ("+15551230420", "Hello, this is the community center reminding you that yoga class starts at 6pm tonight."),
        ("+15551230421", "Hi, it's Aunt May, happy birthday sweetheart, we love you and hope you have a wonderful day."),
        ("+15551230422", "This is the hotel front desk confirming your reservation for two nights this weekend."),
        ("+15551230423", "Hey, it's Priya, are we still carpooling tomorrow morning? I can pick you up at 7:45."),
        ("+15551230424", "This is the moving company, we're confirming your move date for the 15th, the crew arrives at 9am."),
        ("+15551230425", "Hi, just the coach calling, practice is moved to the east field today, see the team there at 4."),
    ]
    records = []
    for caller, transcript in vish:
        records.append(({"caller_id": caller, "transcript": transcript}, 1))
    for caller, transcript in legit:
        records.append(({"caller_id": caller, "transcript": transcript}, 0))
    return records


detector = ChannelDetector(
    name="VishGuard",
    model_path=MODEL_PATH,
    text_fn=_voice_text,
    numeric_fn=_voice_numeric_features,
    num_features=NUM_VOICE_FEATURES,
    seed_fn=_seed_corpus,
    artifact_digest_env="VISH_MODEL_SHA256",
)

# Backwards-compatible class alias.
VishingDetector = ChannelDetector


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    tests = [
        {"caller_id": "IRS", "transcript": "This is the IRS, a warrant is issued for your arrest. Press 1 to settle your tax debt now."},
        {"caller_id": "+15551230401", "transcript": "Hi, this is Dr. Lee's office confirming your appointment Thursday at 3pm."},
    ]
    for t in tests:
        pred, conf = detector.predict(t)
        print(f"[{'VISH' if pred else 'SAFE'}] conf={conf:.2%}  {t['transcript'][:60]}")

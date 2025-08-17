from dataclasses import dataclass, field
from typing import Optional, List
import numpy as np

@dataclass
class Message:
    '''
    Unified data schema for all message types (email, sms, voice).
    Fill in the relevant fields for each message type; unused fields can be left as None.
    '''
    type: str  # 'email', 'sms', or 'voice'
    sender: Optional[str] = None  # Email or phone number
    recipient: Optional[str] = None  # Email or phone number
    subject: Optional[str] = None  # Email subject
    body: Optional[str] = None  # Email or SMS body
    transcript: Optional[str] = None  # Voice call transcript
    date: Optional[str] = None  # ISO format date/time
    provider: Optional[str] = None  # e.g., 'gmail', 'twilio', etc.
    embedding: Optional[np.ndarray] = None  # Embedding vector (numpy array)
    spam: Optional[int] = None  # 0 = not spam, 1 = spam
    confidence: Optional[float] = None  # ML model confidence score
    quarantined: Optional[bool] = None  # Quarantine status
    blocklisted: Optional[bool] = None  # Blocklist status
    user_action: Optional[str] = None  # e.g., 'flagged', 'reported'
    attachment_hashes: Optional[List[str]] = field(default_factory=list)  # List of hashes
    auth_results: Optional[str] = None  # SPF/DKIM/DMARC results (emails)
    message_id: Optional[str] = None  # Email Message-ID
    ip_address: Optional[str] = None  # Sender IP (if available)
    carrier: Optional[str] = None  # SMS/voice carrier info
    call_duration: Optional[int] = None  # Voice call duration (seconds)
    recording_hash: Optional[str] = None  # Hash of call recording
    created_at: Optional[str] = None  # Timestamp

    '''
    For each fetcher (email, sms, voice), create a Message object and fill in the fields relevant to that type.
    Example for email: type='email', sender, recipient, subject, body, etc.
    Example for sms: type='sms', sender, recipient, body, etc.
    Example for voice: type='voice', sender, recipient, transcript, call_duration, etc.
    '''
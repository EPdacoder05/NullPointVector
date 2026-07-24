"""
VishGuard CallKit integration layer — the hybrid (reputation + transcription)
bridge between Apple CallKit events and the VishGuard model.

See docs/CALLKIT_DATA_CONTRACT.md for the wire format the iOS client builds against.

Public surface:
    from common.vish import CallEvent, screen_call
"""
from common.vish.contract import CallEvent, CallKitAction, ScreenResult
from common.vish.adapter import screen_call

__all__ = ["CallEvent", "CallKitAction", "ScreenResult", "screen_call"]

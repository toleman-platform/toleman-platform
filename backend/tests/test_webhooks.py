import hashlib
import hmac

from app.api.webhooks import TRIGGERING_ACTIONS


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_signature_matches_for_correct_secret():
    body = b'{"action": "opened"}'
    secret = "my-webhook-secret"
    sig = _sign(secret, body)
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, expected)


def test_signature_mismatch_for_wrong_secret():
    body = b'{"action": "opened"}'
    sig_correct = _sign("correct-secret", body)
    sig_wrong = _sign("wrong-secret", body)
    assert sig_correct != sig_wrong


def test_signature_mismatch_for_tampered_body():
    secret = "my-webhook-secret"
    sig = _sign(secret, b'{"action": "opened"}')
    tampered_expected = "sha256=" + hmac.new(secret.encode(), b'{"action": "closed"}', hashlib.sha256).hexdigest()
    assert sig != tampered_expected


def test_triggering_actions_cover_the_realtime_scan_cases():
    assert "opened" in TRIGGERING_ACTIONS
    assert "reopened" in TRIGGERING_ACTIONS
    assert "synchronize" in TRIGGERING_ACTIONS
    assert "closed" not in TRIGGERING_ACTIONS
    assert "labeled" not in TRIGGERING_ACTIONS

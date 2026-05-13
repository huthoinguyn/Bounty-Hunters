import hmac

from tls_handshake import TLSHandshake


def test_verify_finished_uses_compare_digest(monkeypatch):
    hs = TLSHandshake()
    hs.master_secret = b"m" * 48
    hs.handshake_hash.update(b"handshake-transcript")

    called = {"used": False}

    def fake_prf(secret, label, seed, output_len):
        return b"\x11" * output_len

    def fake_compare_digest(a, b):
        called["used"] = True
        return True

    monkeypatch.setattr(hs, "_prf", fake_prf)
    monkeypatch.setattr(hmac, "compare_digest", fake_compare_digest)

    assert hs.verify_finished(b"\x11" * 12, "client finished") is True
    assert called["used"] is True


def test_verify_finished_false_on_mismatch():
    hs = TLSHandshake()
    hs.master_secret = b"m" * 48
    hs.handshake_hash.update(b"transcript")

    assert hs.verify_finished(b"\x00" * 12, "client finished") is False

from app.security import hash_password, verify_password
from app.services.traffic import quote_identifier


def test_password_hash_roundtrip() -> None:
    encoded = hash_password("correct-horse-battery-staple")
    assert encoded != "correct-horse-battery-staple"
    assert verify_password("correct-horse-battery-staple", encoded)
    assert not verify_password("wrong-password", encoded)


def test_identifier_quoting() -> None:
    assert quote_identifier('traffic"table') == '"traffic""table"'


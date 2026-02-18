"""
Tests for starspring_security password encoders.
"""
import warnings
import pytest

from starspring_security import (
    BCryptPasswordEncoder,
    Argon2PasswordEncoder,
    Sha256PasswordEncoder,
)


# ─── BCrypt ───────────────────────────────────────────────────────────────────

class TestBCryptPasswordEncoder:

    def setup_method(self):
        self.encoder = BCryptPasswordEncoder()

    def test_encode_returns_string(self):
        hashed = self.encoder.encode("password123")
        assert isinstance(hashed, str)

    def test_encode_is_not_plain_text(self):
        hashed = self.encoder.encode("password123")
        assert hashed != "password123"

    def test_encode_produces_different_hashes(self):
        # BCrypt uses random salt — same password gives different hashes
        h1 = self.encoder.encode("password123")
        h2 = self.encoder.encode("password123")
        assert h1 != h2

    def test_matches_correct_password(self):
        hashed = self.encoder.encode("correct_password")
        assert self.encoder.matches("correct_password", hashed) is True

    def test_matches_wrong_password(self):
        hashed = self.encoder.encode("correct_password")
        assert self.encoder.matches("wrong_password", hashed) is False

    def test_matches_empty_password(self):
        hashed = self.encoder.encode("")
        assert self.encoder.matches("", hashed) is True
        assert self.encoder.matches("not_empty", hashed) is False

    def test_custom_rounds(self):
        encoder = BCryptPasswordEncoder(rounds=4)  # Low for speed in tests
        hashed = encoder.encode("password")
        assert encoder.matches("password", hashed) is True

    def test_invalid_rounds_too_low(self):
        with pytest.raises(ValueError):
            BCryptPasswordEncoder(rounds=3)

    def test_invalid_rounds_too_high(self):
        with pytest.raises(ValueError):
            BCryptPasswordEncoder(rounds=32)


# ─── Argon2 ───────────────────────────────────────────────────────────────────

class TestArgon2PasswordEncoder:

    def setup_method(self):
        self.encoder = Argon2PasswordEncoder()

    def test_encode_returns_string(self):
        hashed = self.encoder.encode("password123")
        assert isinstance(hashed, str)

    def test_encode_is_not_plain_text(self):
        hashed = self.encoder.encode("password123")
        assert hashed != "password123"

    def test_encode_produces_different_hashes(self):
        h1 = self.encoder.encode("password123")
        h2 = self.encoder.encode("password123")
        assert h1 != h2

    def test_matches_correct_password(self):
        hashed = self.encoder.encode("correct_password")
        assert self.encoder.matches("correct_password", hashed) is True

    def test_matches_wrong_password(self):
        hashed = self.encoder.encode("correct_password")
        assert self.encoder.matches("wrong_password", hashed) is False

    def test_matches_returns_false_on_invalid_hash(self):
        assert self.encoder.matches("password", "not_a_valid_hash") is False


# ─── SHA-256 (Deprecated) ─────────────────────────────────────────────────────

class TestSha256PasswordEncoder:

    def setup_method(self):
        self.encoder = Sha256PasswordEncoder()

    def test_encode_raises_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.encoder.encode("password")
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated" in str(w[0].message).lower()

    def test_matches_raises_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            hashed = self.encoder.encode("password")
            self.encoder.matches("password", hashed)
            assert any(issubclass(x.category, DeprecationWarning) for x in w)

    def test_encode_produces_different_hashes(self):
        # SHA-256 encoder uses random salt too
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            h1 = self.encoder.encode("password123")
            h2 = self.encoder.encode("password123")
            assert h1 != h2

    def test_matches_correct_password(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hashed = self.encoder.encode("correct_password")
            assert self.encoder.matches("correct_password", hashed) is True

    def test_matches_wrong_password(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hashed = self.encoder.encode("correct_password")
            assert self.encoder.matches("wrong_password", hashed) is False

    def test_matches_returns_false_on_invalid_hash(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert self.encoder.matches("password", "no_separator_here") is False

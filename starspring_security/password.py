"""
Password encoding implementations for starspring-security.

Supported algorithms:
- BCrypt (default, recommended)
- Argon2 (modern, memory-hard)
- SHA-256 (deprecated, not recommended for passwords)
"""

import abc
import hashlib
import warnings


class PasswordEncoder(abc.ABC):
    """
    Abstract base class for all password encoders.

    Works with any Python web framework:
    StarSpring, FastAPI, Flask, Django, etc.
    """

    @abc.abstractmethod
    def encode(self, raw_password: str) -> str:
        """
        Hash a raw password string.

        Args:
            raw_password: The plain-text password to hash.

        Returns:
            The hashed password string.
        """
        ...

    @abc.abstractmethod
    def matches(self, raw_password: str, encoded_password: str) -> bool:
        """
        Verify a raw password against an encoded password.

        Args:
            raw_password: The plain-text password to verify.
            encoded_password: The previously hashed password.

        Returns:
            True if the password matches, False otherwise.
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class BCryptPasswordEncoder(PasswordEncoder):
    """
    BCrypt password encoder (default, recommended).

    BCrypt is slow by design, making brute-force attacks expensive.
    Automatically salts every password — no need to manage salts manually.

    Requires: pip install starspring-security[bcrypt]

    Example:
        encoder = BCryptPasswordEncoder()
        hashed = encoder.encode("my_password")
        encoder.matches("my_password", hashed)  # True

        # Custom rounds (default: 12, range: 4-31)
        encoder = BCryptPasswordEncoder(rounds=14)
    """

    def __init__(self, rounds: int = 12):
        """
        Args:
            rounds: Work factor (cost). Higher = slower = more secure.
                    Default is 12. Each increment doubles the time.
        """
        if not (4 <= rounds <= 31):
            raise ValueError("BCrypt rounds must be between 4 and 31.")
        self.rounds = rounds
        self._bcrypt = self._import_bcrypt()

    @staticmethod
    def _import_bcrypt():
        try:
            import bcrypt
            return bcrypt
        except ImportError:
            raise ImportError(
                "BCrypt is not installed. "
                "Install it with: pip install starspring-security[bcrypt]"
            )

    def encode(self, raw_password: str) -> str:
        salt = self._bcrypt.gensalt(rounds=self.rounds)
        hashed = self._bcrypt.hashpw(raw_password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def matches(self, raw_password: str, encoded_password: str) -> bool:
        return self._bcrypt.checkpw(
            raw_password.encode("utf-8"),
            encoded_password.encode("utf-8"),
        )


class Argon2PasswordEncoder(PasswordEncoder):
    """
    Argon2 password encoder (modern, memory-hard).

    Argon2 is the winner of the Password Hashing Competition (2015).
    More secure than BCrypt against GPU-based attacks due to memory hardness.

    Requires: pip install starspring-security[argon2]

    Example:
        encoder = Argon2PasswordEncoder()
        hashed = encoder.encode("my_password")
        encoder.matches("my_password", hashed)  # True
    """

    def __init__(
        self,
        time_cost: int = 2,
        memory_cost: int = 65536,
        parallelism: int = 2,
    ):
        """
        Args:
            time_cost: Number of iterations (default: 2)
            memory_cost: Memory usage in kibibytes (default: 65536 = 64MB)
            parallelism: Number of parallel threads (default: 2)
        """
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self._ph = self._import_argon2()

    def _import_argon2(self):
        try:
            from argon2 import PasswordHasher
            return PasswordHasher(
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
            )
        except ImportError:
            raise ImportError(
                "Argon2 is not installed. "
                "Install it with: pip install starspring-security[argon2]"
            )

    def encode(self, raw_password: str) -> str:
        return self._ph.hash(raw_password)

    def matches(self, raw_password: str, encoded_password: str) -> bool:
        try:
            return self._ph.verify(encoded_password, raw_password)
        except Exception:
            return False


class Sha256PasswordEncoder(PasswordEncoder):
    """
    SHA-256 password encoder.

    .. deprecated::
        SHA-256 is a fast hashing algorithm — it is NOT recommended for
        password hashing because it is vulnerable to brute-force and
        rainbow table attacks. Use BCryptPasswordEncoder or
        Argon2PasswordEncoder instead.

    This implementation adds a salt to mitigate rainbow table attacks,
    but SHA-256 remains fundamentally unsuitable for passwords due to
    its speed.

    No extra dependencies required (uses Python's built-in hashlib).

    Example:
        import warnings
        warnings.warn(...)  # You will see a DeprecationWarning

        encoder = Sha256PasswordEncoder()
        hashed = encoder.encode("my_password")
        encoder.matches("my_password", hashed)  # True
    """

    _SEPARATOR = "$"

    def encode(self, raw_password: str) -> str:
        warnings.warn(
            "Sha256PasswordEncoder is deprecated and NOT recommended for "
            "password hashing. SHA-256 is too fast and vulnerable to "
            "brute-force attacks. Use BCryptPasswordEncoder or "
            "Argon2PasswordEncoder instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        import os
        salt = os.urandom(16).hex()
        hashed = hashlib.sha256(f"{salt}{raw_password}".encode()).hexdigest()
        return f"{salt}{self._SEPARATOR}{hashed}"

    def matches(self, raw_password: str, encoded_password: str) -> bool:
        warnings.warn(
            "Sha256PasswordEncoder is deprecated and NOT recommended for "
            "password hashing. SHA-256 is too fast and vulnerable to "
            "brute-force attacks. Use BCryptPasswordEncoder or "
            "Argon2PasswordEncoder instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            salt, stored_hash = encoded_password.split(self._SEPARATOR, 1)
            computed = hashlib.sha256(f"{salt}{raw_password}".encode()).hexdigest()
            return computed == stored_hash
        except ValueError:
            return False

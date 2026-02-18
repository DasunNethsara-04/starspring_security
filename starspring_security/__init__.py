"""
starspring-security — Password hashing utilities.

Works with any Python web framework: StarSpring, FastAPI, Flask, Django, etc.
"""

from starspring_security.password import (
    PasswordEncoder,
    BCryptPasswordEncoder,
    Argon2PasswordEncoder,
    Sha256PasswordEncoder,
)

__version__ = "0.1.0"

__all__ = [
    "PasswordEncoder",
    "BCryptPasswordEncoder",
    "Argon2PasswordEncoder",
    "Sha256PasswordEncoder",
]

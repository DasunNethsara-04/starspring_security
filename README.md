# starspring-security

[![PyPI](https://img.shields.io/pypi/v/starspring-security)](https://pypi.org/project/starspring-security/)
[![Python](https://img.shields.io/pypi/pyversions/starspring-security)](https://pypi.org/project/starspring-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Standalone password hashing utilities for any Python web framework.

Works with **StarSpring**, **FastAPI**, **Flask**, **Django**, or any Python project.

---

## Installation

Choose the algorithm you need:

```bash
# BCrypt (recommended — default)
pip install starspring-security[bcrypt]

# Argon2 (modern, memory-hard)
pip install starspring-security[argon2]

# Both
pip install starspring-security[all]
```

---

## Quick Start

```python
from starspring_security import BCryptPasswordEncoder

encoder = BCryptPasswordEncoder()

# Hash a password
hashed = encoder.encode("my_secret_password")

# Verify a password
encoder.matches("my_secret_password", hashed)   # True
encoder.matches("wrong_password", hashed)        # False
```

---

## Encoders

### `BCryptPasswordEncoder` ✅ Recommended

BCrypt is slow by design — making brute-force attacks expensive.
Automatically salts every password.

```python
from starspring_security import BCryptPasswordEncoder

encoder = BCryptPasswordEncoder()          # Default: rounds=12
encoder = BCryptPasswordEncoder(rounds=14) # Stronger (slower)

hashed = encoder.encode("password")
encoder.matches("password", hashed)  # True
```

### `Argon2PasswordEncoder` ✅ Modern

Winner of the Password Hashing Competition (2015).
More resistant to GPU attacks than BCrypt due to memory hardness.

```python
from starspring_security import Argon2PasswordEncoder

encoder = Argon2PasswordEncoder()
hashed = encoder.encode("password")
encoder.matches("password", hashed)  # True

# Custom parameters
encoder = Argon2PasswordEncoder(time_cost=3, memory_cost=65536, parallelism=2)
```

### `Sha256PasswordEncoder` ⚠️ Deprecated

SHA-256 is **not recommended** for passwords — it is too fast and
vulnerable to brute-force attacks. Use BCrypt or Argon2 instead.

Included for legacy/migration purposes only. Raises a `DeprecationWarning`.

```python
from starspring_security import Sha256PasswordEncoder

encoder = Sha256PasswordEncoder()  # ⚠️ DeprecationWarning raised
hashed = encoder.encode("password")
encoder.matches("password", hashed)  # True
```

---

## Framework Examples

### StarSpring

```python
from starspring import Service, Transactional
from starspring_security import BCryptPasswordEncoder

encoder = BCryptPasswordEncoder()

@Service
class UserService:
    def __init__(self, user_repo):
        self.user_repo = user_repo

    @Transactional
    async def register(self, username: str, password: str):
        user = User(username=username, password=encoder.encode(password))
        return await self.user_repo.save(user)

    async def authenticate(self, username: str, password: str):
        user = await self.user_repo.find_by_username(username)
        if user and encoder.matches(password, user.password):
            return user
        return None
```

### FastAPI

```python
from fastapi import FastAPI, HTTPException
from starspring_security import BCryptPasswordEncoder

app = FastAPI()
encoder = BCryptPasswordEncoder()

@app.post("/register")
def register(username: str, password: str):
    hashed = encoder.encode(password)
    # save to DB...

@app.post("/login")
def login(username: str, password: str):
    user = get_user(username)  # from DB
    if not encoder.matches(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
```

### Flask

```python
from flask import Flask
from starspring_security import BCryptPasswordEncoder

app = Flask(__name__)
encoder = BCryptPasswordEncoder()

@app.route("/register", methods=["POST"])
def register():
    hashed = encoder.encode(request.form["password"])
    # save to DB...

@app.route("/login", methods=["POST"])
def login():
    user = get_user(request.form["username"])
    if not encoder.matches(request.form["password"], user.password):
        return "Invalid credentials", 401
```

### Django

```python
from starspring_security import BCryptPasswordEncoder

encoder = BCryptPasswordEncoder()

# In your view or service
def create_user(username, password):
    hashed = encoder.encode(password)
    User.objects.create(username=username, password=hashed)

def authenticate(username, password):
    user = User.objects.get(username=username)
    return encoder.matches(password, user.password)
```

---

## Algorithm Comparison

| | BCrypt | Argon2 | SHA-256 |
|---|---|---|---|
| **Recommended** | ✅ Yes | ✅ Yes | ❌ No |
| **Auto-salted** | ✅ Yes | ✅ Yes | ✅ Yes (in this lib) |
| **Brute-force resistant** | ✅ Yes | ✅ Yes | ❌ No |
| **GPU resistant** | ⚠️ Partial | ✅ Yes | ❌ No |
| **Extra dependency** | `bcrypt` | `argon2-cffi` | None |

---

## License

MIT — see [LICENSE](LICENSE)

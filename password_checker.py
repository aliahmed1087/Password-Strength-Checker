"""
password_checker.py
-------------------
Core logic for the Password Strength Checker.
No UI code lives here, so it can be tested and reused independently.
"""

import math
import re
import secrets
import string
from dataclasses import dataclass, field

# A small list of very common passwords (lowercase). Extend it if you like.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "1234567", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123",
    "111111", "000000", "iloveyou", "admin", "admin123", "welcome", "welcome1",
    "letmein", "monkey", "dragon", "football", "baseball", "sunshine",
    "princess", "login", "master", "hello", "freedom", "whatever", "trustno1",
    "passw0rd", "p@ssw0rd", "p@ssword", "zaq12wsx", "1q2w3e4r", "iloveyou1",
    "superman", "batman", "shadow", "michael", "jordan", "pakistan", "pakistan123",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

SPECIAL_CHARS = string.punctuation


@dataclass
class Result:
    score: int                      # 0 - 100
    label: str                      # Very Weak ... Very Strong
    entropy: float                  # estimated bits of entropy
    checks: dict = field(default_factory=dict)       # requirement -> bool
    suggestions: list = field(default_factory=list)  # improvement tips
    warnings: list = field(default_factory=list)     # detected weak patterns
    crack_time: str = ""            # human readable estimate


def _has_sequence(pw: str, length: int = 4) -> bool:
    """Detect runs like 'abcd', '1234', 'qwer' (forward or backward)."""
    lowered = pw.lower()
    sources = KEYBOARD_ROWS + [string.ascii_lowercase]
    for src in sources:
        for seq in (src, src[::-1]):
            for i in range(len(seq) - length + 1):
                if seq[i:i + length] in lowered:
                    return True
    return False


def _has_repeats(pw: str, length: int = 3) -> bool:
    """Detect the same character repeated, e.g. 'aaa' or '1111'."""
    return re.search(r"(.)\1{%d,}" % (length - 1), pw) is not None


def _pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[%s]" % re.escape(SPECIAL_CHARS), pw):
        pool += len(SPECIAL_CHARS)
    if re.search(r"[^\x00-\x7F]|\s", pw):
        pool += 20  # spaces / unicode characters
    return pool


def _format_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("second", 60),
        ("minute", 60),
        ("hour", 24),
        ("day", 365),
        ("year", 100),
        ("century", 10),
    ]
    value = seconds
    for name, factor in units:
        if value < factor:
            n = int(value)
            return f"{n} {name}{'s' if n != 1 else ''}"
        value /= factor
    if value < 1000:
        return f"{int(value)} millennia"
    return "millions of years"


def check_password(pw: str) -> Result:
    if not pw:
        return Result(0, "Empty", 0.0, crack_time="")

    checks = {
        "At least 8 characters": len(pw) >= 8,
        "At least 12 characters (recommended)": len(pw) >= 12,
        "Contains lowercase letter (a-z)": bool(re.search(r"[a-z]", pw)),
        "Contains uppercase letter (A-Z)": bool(re.search(r"[A-Z]", pw)),
        "Contains a number (0-9)": bool(re.search(r"\d", pw)),
        "Contains a special character (!@#$...)": bool(
            re.search(r"[%s]" % re.escape(SPECIAL_CHARS), pw)
        ),
    }

    warnings, suggestions = [], []

    # ---- Entropy estimate ----
    pool = _pool_size(pw)
    entropy = len(pw) * math.log2(pool) if pool else 0.0

    # ---- Weak pattern penalties ----
    penalty = 0
    lowered = pw.lower()

    if lowered in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords.")
        penalty += 60
    elif any(c in lowered for c in COMMON_PASSWORDS if len(c) >= 6):
        warnings.append("Contains a very common password or word.")
        penalty += 25

    if _has_sequence(pw):
        warnings.append("Contains a predictable sequence (e.g. abcd, 1234, qwer).")
        penalty += 15
        entropy *= 0.8

    if _has_repeats(pw):
        warnings.append("Contains repeated characters (e.g. aaa, 111).")
        penalty += 10
        entropy *= 0.85

    if len(set(pw)) <= max(3, len(pw) // 3):
        warnings.append("Uses very few unique characters.")
        penalty += 10
        entropy *= 0.8

    if pw.isdigit():
        warnings.append("Contains only numbers.")
        penalty += 10
    elif pw.isalpha():
        warnings.append("Contains only letters.")
        penalty += 5

    # ---- Score (0-100) ----
    # Entropy of ~80 bits is treated as "fully strong".
    base = min(entropy / 80, 1.0) * 100
    score = int(max(0, min(100, base - penalty)))

    # Hard caps so short passwords can never look "strong"
    if len(pw) < 6:
        score = min(score, 15)
    elif len(pw) < 8:
        score = min(score, 35)
    if lowered in COMMON_PASSWORDS:
        score = min(score, 5)

    # ---- Label ----
    if score < 20:
        label = "Very Weak"
    elif score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    # ---- Suggestions ----
    if len(pw) < 12:
        suggestions.append("Make it longer: 12+ characters is much harder to crack.")
    if not checks["Contains uppercase letter (A-Z)"]:
        suggestions.append("Add uppercase letters.")
    if not checks["Contains lowercase letter (a-z)"]:
        suggestions.append("Add lowercase letters.")
    if not checks["Contains a number (0-9)"]:
        suggestions.append("Add numbers.")
    if not checks["Contains a special character (!@#$...)"]:
        suggestions.append("Add special characters such as ! @ # $ % ^ &.")
    if warnings:
        suggestions.append("Avoid common words, sequences and repeated characters.")
    if score >= 80 and not suggestions:
        suggestions.append("Great password! Use a unique one for every account.")

    # ---- Crack time (assume 10 billion guesses/second offline attack) ----
    guesses = 2 ** entropy
    crack_time = _format_time(guesses / 2 / 1e10)
    if lowered in COMMON_PASSWORDS:
        crack_time = "instantly"

    return Result(score, label, round(entropy, 1), checks, suggestions, warnings, crack_time)


def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    length = max(length, 12)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*()-_=+?" for c in pw)
        ):
            return pw

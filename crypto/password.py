import bcrypt

def hash_password(password: str) -> str:
    """Hash password using bcrypt with random salt and cost factor 12."""
    if not password:
        raise ValueError("Password cannot be empty")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash in constant time."""
    if not password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Ensure password meets enterprise security standards."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase letters, and digits"
    return True, "Password meets complexity standards"

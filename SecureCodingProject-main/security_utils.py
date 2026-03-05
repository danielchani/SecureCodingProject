import hashlib  # Library for hashing algorithms (SHA256)
import hmac     # Library for HMAC (Keyed-Hashing for Message Authentication)
import os       # Library for OS interactions (generating random bytes)
import re       # Library for Regular Expressions (Password validation)
import json     # Library to parse JSON configuration files

# Load security configuration from external file
CONFIG_FILE = 'config.json'

def load_config():
    """Reads security policies from config.json."""
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# Initialize config
config = load_config()
POLICY = config['password_policy']


def validate_password(password):
    """
    Checks if a password meets the complexity requirements.
    Returns: (bool, str) -> (IsValid, ErrorMessage)
    """
    # Check minimum length
    if len(password) < POLICY['min_length']:
        return False, f"Password must be at least {POLICY['min_length']} characters."

    # Check for uppercase letters
    if POLICY['require_uppercase'] and not any(char.isupper() for char in password):
        return False, "Password must contain an uppercase letter."

    # Check for lowercase letters
    if POLICY['require_lowercase'] and not any(char.islower() for char in password):
        return False, "Password must contain a lowercase letter."

    # Check for numbers
    if POLICY['require_numbers'] and not any(char.isdigit() for char in password):
        return False, "Password must contain a number."

    # Check for special characters using a predefined set
    # FIX: removed invalid escape sequence \|
    specials = "!@#$%^&*()-_=+[{]}|;:'\",<.>/?"
    if POLICY['require_special_chars'] and not any(char in specials for char in password):
        return False, "Password must contain a special character."

    return True, "Valid"


def generate_salt(length: int = 16) -> str:
    """Generates a random salt (hex)."""
    return os.urandom(length).hex()


def hash_password(password, salt=None):
    """
    Creates a secure HMAC-SHA256 hash.
    If salt is not provided, generates a new random salt.
    Returns: (hash_hex, salt)
    """
    if salt is None:
        salt = generate_salt(16)

    # Create HMAC object using the salt as the key and SHA256 as the algorithm
    h = hmac.new(
        key=salt.encode('utf-8'),
        msg=password.encode('utf-8'),
        digestmod=hashlib.sha256
    )

    return h.hexdigest(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Verifies password against stored hash + salt."""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == expected_hash


def generate_reset_token():
    """Generates a random SHA-1 token for password resets."""
    random_data = os.urandom(20)
    token = hashlib.sha1(random_data).hexdigest()
    return token

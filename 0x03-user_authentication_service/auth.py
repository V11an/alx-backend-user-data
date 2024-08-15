#!/usr/bin/env python3
"""
Method to hash passwords
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt and returns the salted hash in bytes.

    Args:
        password: The password to hash (string).

    Returns:
        The salted hash of the password (bytes).
    """

    # Encode the password as bytes (recommended for bcrypt)
    password_bytes = password.encode("utf-8")

    # Generate a random salt
    salt = bcrypt.gensalt()

    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password

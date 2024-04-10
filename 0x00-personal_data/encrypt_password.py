#!/usr/bin/env python3
"""A module for hashing password.
"""
import bcrypt

def hash_password(password: str) -> bytes:
    """Hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(encrypted_password: bytes, password: str) -> bool:
    """Verify password validation
    """
    return bcrypt.checkpw(password.encode('utf-8'), encrypted_password)

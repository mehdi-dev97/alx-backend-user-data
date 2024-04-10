#!/usr/bin/env python3
"""A module for hashing password.
"""
import bcrypt

def hash_password(password: str) -> str:
    """Hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

#!/usr/bin/env python3
'''Module for storing the encrypt_password function.'''
import bcrypt


def hash_password(password: str) -> bytes:
    '''Returns a salted, hashed password.'''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''Checks if a password matches a given hash.'''
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

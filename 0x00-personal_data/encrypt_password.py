#!/usr/bin/env python3
"""Task 5 and Task 6 Module for encrypting passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    hash_password: function that expects one string argument name password and
    Returns: a salted, hashed password, which is a byte string
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """function that expects 2 arguments and returns a boolean.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
"""   
def hash_password(password):
    ''' Generate a random salt '''
    salt = bcrypt.gensalt()
    
    ''' Hash the password using the generated salt '''
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password

def is_valid(hashed_password, password):
    ''' Verify if the provided password matches the hashed password '''
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
"""

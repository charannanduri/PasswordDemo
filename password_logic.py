#!/usr/bin/env python3
"""
Core Password Security Logic
"""

import re
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def load_common_passwords(file_path):
    """
    Load common passwords from a file.

    Args:
        file_path (str): Path to the file containing common passwords.

    Returns:
        set: A set of common passwords.
    """
    try:
        with open(file_path, 'r') as file:
            return set(line.strip().lower() for line in file if line.strip())
    except FileNotFoundError:
        print(f"Error: Common passwords file not found at {file_path}.")
        return set()

def check_password_strength(password, username=""):
    """
    Check the strength of a password based on various criteria.

    Args:
        password (str): The password to check
        username (str, optional): The username to check against

    Returns:
        dict: A dictionary with the score and feedback
    """
    score = 0
    feedback = []

    # Check length
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters long.")

    # Check for uppercase and lowercase
    if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should contain both uppercase and lowercase letters.")

    # Check for numbers
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Password should contain at least one number.")

    # Check for special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one special character.")

    # Load common passwords dynamically
    common_passwords_file = os.path.join(os.path.dirname(__file__), 'data', 'common_passwords.txt')
    common_passwords = load_common_passwords(common_passwords_file)

    if password.lower() in common_passwords:
        score = 0
        # Replace previous feedback if common password is found
        feedback = ["This is a commonly used password. Please choose a more unique password."]
    elif username and username.lower() in password.lower():
        # Check for username inclusion only if not a common password
        score = max(0, score - 1)
        feedback.append("Password should not contain your username.")

    return {
        "score": score,
        "feedback": " ".join(feedback) if feedback else "Strong password!"
    }

def hash_password(password):
    """
    Hash a password using SHA-256.

    Args:
        password (str): The password to hash

    Returns:
        str: The SHA-256 hash as a hexadecimal string
    """
    password_bytes = password.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password_bytes)
    return sha256_hash.hexdigest()

def encrypt_hash(hash_value):
    """
    Encrypt a hash value using AES-256 in CBC mode.

    Args:
        hash_value (str): The hash to encrypt

    Returns:
        dict: A dictionary containing the encrypted data, IV, and key (all base64 encoded)
    """
    hash_bytes = hash_value.encode('utf-8')
    key = os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(hash_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')

    return {
        'encrypted_data': encrypted_b64,
        'iv': iv_b64,
        'key': key_b64
    }

def decrypt_hash(encrypted_data, iv, key):
    """
    Decrypt an encrypted hash value using AES-256 in CBC mode.

    Args:
        encrypted_data (str): Base64-encoded encrypted data
        iv (str): Base64-encoded initialization vector
        key (str): Base64-encoded encryption key

    Returns:
        str: The decrypted hash value
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv_bytes = base64.b64decode(iv)
        key_bytes = base64.b64decode(key)

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
        decrypted_hash = decrypted_bytes.decode('utf-8')
        return decrypted_hash
    except Exception as e:
        print(f"Decryption error: {e}") # Log error for debugging
        raise ValueError("Decryption failed. Invalid key, IV, or data.")
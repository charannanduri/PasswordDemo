#!/usr/bin/env python3
"""
Password Security Demonstration - Command Line Interface

This script demonstrates the complete process of:
1. Checking password strength
2. Hashing a password with SHA-256 (only if strong)
3. Encrypting the hash with AES-256 (only if strong)
4. Decrypting the hash (only if strong)
5. Verifying the decryption (only if strong)

This is the command-line version of the application.
"""

import re
import hashlib
import os
import base64
import json
import sys  # Added for exiting early
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
# Import functions from the logic module
from password_logic import (
    check_password_strength, 
    hash_password, 
    encrypt_hash, 
    decrypt_hash
)

def print_separator():
    """Print a separator line."""
    print("\n" + "=" * 60 + "\n")

def run_cli():
    """Main function to run the command-line interface."""
    print("\nPASSWORD SECURITY DEMONSTRATION (CLI)\n")
    
    # Step 1: Get username and password
    username = input("Enter a username: ")
    password = input("Enter a password: ")
    
    print_separator()
    
    # Step 2: Check password strength
    print("STEP 1: PASSWORD STRENGTH ANALYSIS")
    strength = check_password_strength(password, username)
    print(f"Strength score: {strength['score']}/4")
    print(f"Feedback: {strength['feedback']}")

    # Check if the password is strong enough to proceed
    if strength['score'] < 4:
        print("\nPassword is not strong enough. Please choose a stronger password.")
        sys.exit() # Exit the script if the password is weak
    else:
        print("\nPassword is strong. Proceeding with hashing and encryption.")

    print_separator()
    
    # Step 3: Hash the password (only if strong)
    print("STEP 2: PASSWORD HASHING (SHA-256)")
    hashed_password = hash_password(password)
    print(f"Original password: {password}")
    print(f"SHA-256 hash: {hashed_password}")
    
    print_separator()
    
    # Step 4: Encrypt the hash (only if strong)
    print("STEP 3: HASH ENCRYPTION (AES-256)")
    encryption_result = encrypt_hash(hashed_password)
    print("Encrypted hash components:")
    print(f"  IV: {encryption_result['iv'][:20]}...")
    print(f"  Encrypted data: {encryption_result['encrypted_data'][:20]}...")
    print(f"  Key: {encryption_result['key'][:20]}...")
    
    print_separator()
    
    # Step 5: Decrypt the hash (only if strong)
    print("STEP 4: HASH DECRYPTION")
    decrypted_hash = decrypt_hash(
        encryption_result['encrypted_data'],
        encryption_result['iv'],
        encryption_result['key']
    )
    print(f"Decrypted hash: {decrypted_hash}")
    
    print_separator()
    
    # Step 6: Verify the decryption (only if strong)
    print("STEP 5: VERIFICATION")
    if decrypted_hash == hashed_password:
        print("✓ SUCCESS: The decrypted hash matches the original hash.")
    else:
        print("✗ ERROR: The decrypted hash does not match the original hash.")
    
    print_separator()
    
    # Save the results to a file (only if strong)
    result = {
        'username': username,
        'password_strength': strength,
        'hashed_password': hashed_password,
        'encryption': encryption_result,
        'decrypted_hash': decrypted_hash,
        'verification': decrypted_hash == hashed_password
    }
    
    with open('password_security_results.json', 'w') as f:
        json.dump(result, f, indent=2)
    
    print("Results saved to 'password_security_results.json'")
    print("\nThank you for using the Password Security Demonstration!")

if __name__ == "__main__":
    run_cli() # Renamed main to run_cli to avoid conflicts

#!/usr/bin/env python3
"""
SHA-256 Password Hasher

This script demonstrates how to hash passwords using the SHA-256 algorithm.
It shows the step-by-step process of converting a password to a secure hash.
"""

import hashlib
import binascii

def hash_password(password):
    """
    Hash a password using SHA-256 and return the hexadecimal digest.
    
    Args:
        password (str): The password to hash
        
    Returns:
        str: The SHA-256 hash as a hexadecimal string
    """
    # Step 1: Convert the password to bytes
    password_bytes = password.encode('utf-8')
    
    # Step 2: Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Step 3: Update the hash object with the password bytes
    sha256_hash.update(password_bytes)
    
    # Step 4: Get the digest (hash) as a hexadecimal string
    hashed_password = sha256_hash.hexdigest()
    
    return hashed_password

def show_hashing_details(password):
    """
    Display the details of the SHA-256 hashing process for educational purposes.
    
    Args:
        password (str): The password to hash
    """
    print("\n===== SHA-256 Hashing Process =====\n")
    
    # Step 1: Convert to bytes and show ASCII values
    password_bytes = password.encode('utf-8')
    print("Step 1: Convert password to bytes")
    print(f"Original password: {password}")
    print(f"ASCII bytes (hex): {password_bytes.hex(' ')}")
    
    # Step 2: Show information about padding (simplified explanation)
    print("\nStep 2: Padding")
    print("The SHA-256 algorithm pads the message to ensure its length is a multiple of 512 bits.")
    print(f"Original length: {len(password_bytes) * 8} bits")
    padded_length = ((len(password_bytes) * 8 + 1 + 64 + 511) // 512) * 512
    print(f"Padded length: {padded_length} bits")
    
    # Step 3: Show information about processing in chunks
    print("\nStep 3: Process in 512-bit chunks")
    num_chunks = padded_length // 512
    print(f"Number of 512-bit chunks: {num_chunks}")
    
    # Step 4: Show information about the compression function
    print("\nStep 4: Compression Function")
    print("Each chunk is processed through a compression function with 64 rounds.")
    print("Initial hash values (H0-H7):")
    print("6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19")
    
    # Step 5: Compute and show the final hash
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password_bytes)
    hashed_password = sha256_hash.hexdigest()
    
    print("\nStep 5: Final Hash")
    print(f"SHA-256 hash: {hashed_password}")
    
    # Show the hash in 8 blocks of 8 characters (32 bits each)
    print("Hash in 8 blocks (32 bits each):")
    for i in range(0, len(hashed_password), 8):
        print(hashed_password[i:i+8], end=" ")
    print("\n")

def main():
    """Main function to demonstrate password hashing."""
    # Get password from user
    password = input("Enter a password to hash: ")
    
    # Show the hashing details
    show_hashing_details(password)
    
    # Hash the password
    hashed_password = hash_password(password)
    
    # Display the result
    print(f"SHA-256 hash: {hashed_password}")
    print(f"Hash length: {len(hashed_password)} characters ({len(hashed_password) * 4} bits)")

if __name__ == "__main__":
    main()

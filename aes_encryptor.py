#!/usr/bin/env python3
"""
AES Password Encryptor

This script demonstrates how to encrypt a password hash using AES-256 in GCM mode.
It shows the step-by-step process of encrypting data with a secure key and initialization vector.
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_hash(hash_value, key=None):
    """
    Encrypt a hash value using AES-256 in CBC mode.
    
    Args:
        hash_value (str): The hash to encrypt
        key (bytes, optional): The encryption key. If None, a random key is generated.
        
    Returns:
        dict: A dictionary containing the encrypted data, IV, and key
    """
    # Step 1: Convert the hash to bytes
    hash_bytes = hash_value.encode('utf-8')
    
    # Step 2: Generate a random 256-bit (32-byte) key if not provided
    if key is None:
        key = os.urandom(32)  # 256 bits = 32 bytes
    
    # Step 3: Generate a random 128-bit (16-byte) initialization vector (IV)
    iv = os.urandom(16)  # 128 bits = 16 bytes
    
    # Step 4: Create a padder to ensure the data is a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(hash_bytes) + padder.finalize()
    
    # Step 5: Create an AES cipher with the key and IV
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Step 6: Create an encryptor and encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Step 7: Encode the binary data as base64 for storage/transmission
    encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')
    
    # Return the encrypted data, IV, and key
    return {
        'encrypted_data': encrypted_b64,
        'iv': iv_b64,
        'key': key_b64
    }

def show_encryption_details(hash_value, encryption_result):
    """
    Display the details of the AES encryption process for educational purposes.
    
    Args:
        hash_value (str): The original hash value
        encryption_result (dict): The result from encrypt_hash
    """
    print("\n===== AES-256 Encryption Process =====\n")
    
    # Step 1: Show the original hash
    print("Step 1: Original Hash Value")
    print(f"Hash: {hash_value}")
    print(f"Length: {len(hash_value)} characters ({len(hash_value.encode('utf-8')) * 8} bits)")
    
    # Step 2: Show the key
    key_bytes = base64.b64decode(encryption_result['key'])
    print("\nStep 2: Encryption Key (AES-256)")
    print(f"Key (base64): {encryption_result['key']}")
    print(f"Key (hex): {key_bytes.hex()}")
    print(f"Key length: {len(key_bytes) * 8} bits")
    
    # Step 3: Show the IV
    iv_bytes = base64.b64decode(encryption_result['iv'])
    print("\nStep 3: Initialization Vector (IV)")
    print(f"IV (base64): {encryption_result['iv']}")
    print(f"IV (hex): {iv_bytes.hex()}")
    print(f"IV length: {len(iv_bytes) * 8} bits")
    
    # Step 4: Show information about padding
    print("\nStep 4: Padding")
    print("The data is padded to ensure its length is a multiple of the AES block size (128 bits).")
    original_length = len(hash_value.encode('utf-8'))
    block_size = 16  # 128 bits = 16 bytes
    padding_length = block_size - (original_length % block_size)
    print(f"Original length: {original_length} bytes")
    print(f"Padded length: {original_length + padding_length} bytes")
    
    # Step 5: Show the encrypted data
    encrypted_bytes = base64.b64decode(encryption_result['encrypted_data'])
    print("\nStep 5: Encrypted Data")
    print(f"Encrypted (base64): {encryption_result['encrypted_data']}")
    print(f"Encrypted (hex): {encrypted_bytes.hex()}")
    print(f"Encrypted length: {len(encrypted_bytes)} bytes")
    
    # Step 6: Show the complete encrypted package
    print("\nStep 6: Complete Encrypted Package")
    print("For secure storage or transmission, we need to keep the encrypted data, IV, and key.")
    print("The encrypted package can be represented as a JSON object:")
    print(json.dumps(encryption_result, indent=2))
    print("\nNOTE: In a real-world scenario, the key would be securely stored separately!")

def main():
    """Main function to demonstrate hash encryption."""
    # Get hash from user or use a sample hash
    choice = input("Do you want to enter a hash value? (y/n): ")
    if choice.lower() == 'y':
        hash_value = input("Enter a hash value to encrypt: ")
    else:
        # Sample SHA-256 hash
        hash_value = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        print(f"Using sample hash: {hash_value}")
    
    # Encrypt the hash
    encryption_result = encrypt_hash(hash_value)
    
    # Show the encryption details
    show_encryption_details(hash_value, encryption_result)
    
    # Save the encryption result to a file for later decryption
    with open('encrypted_hash.json', 'w') as f:
        json.dump(encryption_result, f, indent=2)
    print("\nEncryption result saved to 'encrypted_hash.json' for later decryption.")

if __name__ == "__main__":
    main()

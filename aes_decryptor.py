#!/usr/bin/env python3
"""
AES Password Decryptor

This script demonstrates how to decrypt an encrypted password hash using AES-256 in GCM mode.
It shows the step-by-step process of decrypting data with the provided key and initialization vector.
"""

import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

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
    # Step 1: Decode the base64 strings to binary data
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv_bytes = base64.b64decode(iv)
    key_bytes = base64.b64decode(key)
    
    # Step 2: Create an AES cipher with the key and IV
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CBC(iv_bytes),
        backend=default_backend()
    )
    
    # Step 3: Create a decryptor and decrypt the data
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    # Step 4: Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    # Step 5: Convert the decrypted bytes back to a string
    decrypted_hash = decrypted_bytes.decode('utf-8')
    
    return decrypted_hash

def show_decryption_details(encryption_data, decrypted_hash):
    """
    Display the details of the AES decryption process for educational purposes.
    
    Args:
        encryption_data (dict): The encryption data (encrypted_data, iv, key)
        decrypted_hash (str): The decrypted hash value
    """
    print("\n===== AES-256 Decryption Process =====\n")
    
    # Step 1: Show the encrypted package
    print("Step 1: Encrypted Package")
    print("The encrypted package contains the encrypted data, IV, and key:")
    print(json.dumps(encryption_data, indent=2))
    
    # Step 2: Show the key
    key_bytes = base64.b64decode(encryption_data['key'])
    print("\nStep 2: Encryption Key (AES-256)")
    print(f"Key (base64): {encryption_data['key']}")
    print(f"Key (hex): {key_bytes.hex()}")
    print(f"Key length: {len(key_bytes) * 8} bits")
    
    # Step 3: Show the IV
    iv_bytes = base64.b64decode(encryption_data['iv'])
    print("\nStep 3: Initialization Vector (IV)")
    print(f"IV (base64): {encryption_data['iv']}")
    print(f"IV (hex): {iv_bytes.hex()}")
    print(f"IV length: {len(iv_bytes) * 8} bits")
    
    # Step 4: Show the encrypted data
    encrypted_bytes = base64.b64decode(encryption_data['encrypted_data'])
    print("\nStep 4: Encrypted Data")
    print(f"Encrypted (base64): {encryption_data['encrypted_data']}")
    print(f"Encrypted (hex): {encrypted_bytes.hex()}")
    print(f"Encrypted length: {len(encrypted_bytes)} bytes")
    
    # Step 5: Show the decryption process
    print("\nStep 5: Decryption Process")
    print("1. Create an AES cipher with the key and IV")
    print("2. Decrypt the data using the cipher")
    print("3. Remove the padding from the decrypted data")
    print("4. Convert the decrypted bytes back to a string")
    
    # Step 6: Show the decrypted hash
    print("\nStep 6: Decrypted Hash")
    print(f"Decrypted hash: {decrypted_hash}")
    print(f"Hash length: {len(decrypted_hash)} characters ({len(decrypted_hash.encode('utf-8')) * 8} bits)")
    
    # Step 7: Verification
    print("\nStep 7: Verification")
    print("In a real-world scenario, you would verify that this hash matches the original hash.")
    print("This confirms that the encryption and decryption processes worked correctly.")

def main():
    """Main function to demonstrate hash decryption."""
    try:
        # Try to load the encryption result from the file
        with open('encrypted_hash.json', 'r') as f:
            encryption_data = json.load(f)
        print("Loaded encryption data from 'encrypted_hash.json'")
    except FileNotFoundError:
        # If the file doesn't exist, use sample data
        print("No encryption data file found. Using sample data.")
        encryption_data = {
            'encrypted_data': 'XYZ123...',  # Sample encrypted data
            'iv': 'ABC456...',              # Sample IV
            'key': 'DEF789...'              # Sample key
        }
        
        # Ask the user to input the encryption data
        print("Please enter the encryption data:")
        encryption_data['encrypted_data'] = input("Encrypted data (base64): ")
        encryption_data['iv'] = input("IV (base64): ")
        encryption_data['key'] = input("Key (base64): ")
    
    # Decrypt the hash
    try:
        decrypted_hash = decrypt_hash(
            encryption_data['encrypted_data'],
            encryption_data['iv'],
            encryption_data['key']
        )
        
        # Show the decryption details
        show_decryption_details(encryption_data, decrypted_hash)
        
    except Exception as e:
        print(f"\nError during decryption: {e}")
        print("Please check that the encryption data is correct.")

if __name__ == "__main__":
    main()

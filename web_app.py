#!/usr/bin/env python3
"""
Flask Web Application for Password Security Demo
"""

import os
from flask import Flask, request, jsonify, render_template, send_from_directory
from password_logic import (
    check_password_strength, 
    hash_password, 
    encrypt_hash, 
    decrypt_hash
)

# Ensure templates and static directories exist
if not os.path.exists('templates'):
    os.makedirs('templates')
if not os.path.exists('static'):
    os.makedirs('static')

app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Routes ---

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serves static files (CSS, JS)."""
    return send_from_directory(app.static_folder, filename)

# --- API Endpoints ---

@app.route('/api/check_strength', methods=['POST'])
def api_check_strength():
    """API endpoint to check password strength."""
    data = request.get_json()
    password = data.get('password', '')
    username = data.get('username', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
        
    strength = check_password_strength(password, username)
    return jsonify(strength)

# @app.route('/api/process', methods=['POST'])
def api_process_password(): # Original function, now unused
    # ... (keep old code commented out or remove)
    pass

@app.route('/api/hash', methods=['POST'])
def api_hash():
    """API endpoint to hash a password (strength check assumed done by client)."""
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password is required for hashing'}), 400

    # Note: We could re-check strength here for robustness, but currently trust client
    # strength = check_password_strength(password, "") # Optional re-check
    # if strength['score'] < 4:
    #     return jsonify({'error': 'Password is not strong enough for hashing.'}), 400

    try:
        hashed_password = hash_password(password)
        return jsonify({'hashed_password': hashed_password})
    except Exception as e:
        app.logger.error(f"Error hashing password: {e}")
        return jsonify({'error': 'An internal error occurred during hashing.'}), 500

@app.route('/api/encrypt_hash', methods=['POST'])
def api_encrypt_hash():
    """API endpoint to encrypt a provided hash value."""
    data = request.get_json()
    hash_value = data.get('hash_value', '')

    if not hash_value:
        return jsonify({'error': 'Hashed password is required for encryption'}), 400

    try:
        encryption_result = encrypt_hash(hash_value)
        return jsonify({'encryption': encryption_result})
    except Exception as e:
        app.logger.error(f"Error encrypting hash: {e}")
        return jsonify({'error': 'An internal error occurred during encryption.'}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt_hash():
    """API endpoint to decrypt a hash."""
    data = request.get_json()
    encrypted_data = data.get('encrypted_data')
    iv = data.get('iv')
    key = data.get('key')

    if not all([encrypted_data, iv, key]):
        return jsonify({'error': 'Missing encrypted data, IV, or key'}), 400

    try:
        decrypted_hash_result = decrypt_hash(encrypted_data, iv, key)
        return jsonify({'decrypted_hash': decrypted_hash_result})
    except ValueError as e:
        # Catch specific decryption errors (like padding errors, invalid key etc.)
        app.logger.warning(f"Decryption failed: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Error decrypting hash: {e}")
        return jsonify({'error': 'An internal error occurred during decryption.'}), 500

# Note: The entry point to run the app will be in run.py 
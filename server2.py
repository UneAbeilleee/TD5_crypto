from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from tink import aead
import tink
from flask import Flask, request, jsonify, render_template
import hashlib
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_sqlalchemy import SQLAlchemy
import secrets
import uuid
import base64

app = Flask(__name__)
aead.register()
# Define key size and algorithm
key_size = 128
algorithm = "AES-GCM"

# Create a key template (using aead_key_templates)
key_template = aead.aead_key_templates.AES128_GCM

# Generate a new KeysetHandle
keyset_handle = tink.new_keyset_handle(key_template)
user_salts = []

# Generate a single AEAD primitive for encryption
aead_primitive = keyset_handle.primitive(aead.Aead)
SERVER2_LOGIN_URL = "http://localhost:5001/login"
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    password = data.get('password')

    # Generate a unique salt for each user
    salt = secrets.token_bytes(16)

    # Store the salt in the dictionary with a unique identifier (e.g., username)
    user_salts.append(salt)

    # Use the generated salt for encryption
    hashed_password_with_salt = hash_password(password.encode(), salt)

    # Encrypt with Tink
    ciphertext = aead_primitive.encrypt(hashed_password_with_salt, b'')

    return jsonify({'encryptedHash': base64.b64encode(ciphertext).decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}), 200

# Function to hash the password with salt using SHA-256 (deterministic hash function)
def hash_password(password, salt):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password + salt)  # Concatenate password and salt for hashing
    return digest.finalize()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')
    username = data.get('username')
    position = data.get('position')
    final_pass = None
        # Récupérer le sel associé à l'utilisateur
    salt = user_salts[position]

        # Use the generated salt for encryption
    hashed_password_with_salt = hash_password(password.encode(), salt)

        # Encrypt with Tink
    ciphertext = aead_primitive.encrypt(hashed_password_with_salt, b'')
    final_pass = base64.b64encode(ciphertext).decode('utf-8')

    SERVER1_LOGIN_URL = "http://localhost:5000/login"
    # Renvoyez 'final_pass' et 'username' comme réponse du serveur 2
    print(final_pass)
    return jsonify({'final_pass': final_pass, 'username': username}), 200



if __name__ == '__main__':
    app.run(debug=True, port=5001)

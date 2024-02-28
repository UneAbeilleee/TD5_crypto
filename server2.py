from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from tink import aead
from tink.core import tink_config

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    hashed_password = data.get('hashedPassword')
    if not hashed_password:
        return jsonify({'error': 'Please provide a hashed password'}), 400
    salt = secrets.token_bytes(16)
    hashed_password_with_salt = hash_password(hashed_password.encode(), salt)
    encrypted_hash = encrypt_with_aes(hashed_password_with_salt)
    
    return jsonify({'encryptedHash': encrypted_hash, 'salt': base64.b64encode(salt).decode('utf-8')}), 200

def encrypt_with_aes(data):
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode('utf-8')

# Function to hash the password with salt using PBKDF2HMAC
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

if __name__ == '__main__':
    app.run(debug=True, port=5001)

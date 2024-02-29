from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from tink import aead, daead,core
import bcrypt
import tink

app = Flask(__name__)
daead.register()
keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
user_salts = []

# Generate a single AEAD primitive for encryption
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)
SERVER2_LOGIN_URL = "http://localhost:5001"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    password = data.get('password')

    # Generate a unique salt for each user
    salt = bcrypt.gensalt()
    print(salt)
    user_salts.append(salt)
    password_bytes = password.encode()
    

    # Use the generated salt for encryption
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    print(hashed_password)
    

    # Encrypt with Tink
    ciphertext = daead_primitive.encrypt_deterministically(hashed_password, b'')
    print(ciphertext)
    print(base64.b64encode(ciphertext).decode('utf-8'))

    return jsonify({'encryptedHash': base64.b64encode(ciphertext).decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')
    username = data.get('username')
    position = data.get('position')
    final_pass = None
    print(position)
    salt = user_salts[position]
    print(salt)
    password_bytes = password.encode()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    print(hashed_password)
    ciphertext = daead_primitive.encrypt_deterministically(hashed_password, b'')
    print(ciphertext)
    final_pass = base64.b64encode(ciphertext).decode('utf-8')

    SERVER1_LOGIN_URL = "http://localhost:5000/login"
    print(final_pass)
    return jsonify({'final_pass': final_pass, 'username': username}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)


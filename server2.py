
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from tink import aead, daead,core
import bcrypt
import tink
import os

app = Flask(__name__)
daead.register()
keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)

# Generate a single AEAD primitive for encryption
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)
SERVER2_LOGIN_URL = "http://localhost:5001"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    hashed_password = data.get('password')
    hashed_password=hashed_password.encode()

    # Encrypt with Tink
    ciphertext = daead_primitive.encrypt_deterministically(hashed_password, b'')
    print(ciphertext)
    print(base64.b64encode(ciphertext).decode('utf-8'))

    return jsonify({'encryptedHash': base64.b64encode(ciphertext).decode('utf-8')}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5001)



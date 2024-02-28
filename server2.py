from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from tink import aead
import tink

app = Flask(__name__)
aead.register()
# Define key size and algorithm
key_size = 128
algorithm = "AES-GCM"

# Create a key template (using aead_key_templates)
key_template = aead.aead_key_templates.AES128_GCM

# Generate a new KeysetHandle
keyset_handle = tink.new_keyset_handle(key_template)

# Generate a single salt for all encryption operations

# Generate a single AEAD primitive for encryption
aead_primitive = keyset_handle.primitive(aead.Aead)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    password = data.get('password')
    salt_base64 = data.get('salt')
    salt = base64.b64decode(salt_base64)

    # Use the same salt for all encryption operations
    hashed_password_with_salt = hash_password(password.encode(), salt)

    # Encrypt with Tink
    ciphertext = aead_primitive.encrypt(hashed_password_with_salt, b'') 
    return jsonify({'encryptedHash': base64.b64encode(ciphertext).decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}), 200

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

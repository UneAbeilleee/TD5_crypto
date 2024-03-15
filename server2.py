
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

user_salt_file = "users_salt.txt"
user_entropy_file = "users_entropy.txt"

if not os.path.exists(user_salt_file):
    with open(user_salt_file, 'w'):
        pass

if not os.path.exists(user_entropy_file):
    with open(user_entropy_file, 'w'):
        pass
        
def read_salts_from_file():
    with open(user_salt_file, 'r') as f:
        return [base64.b64decode(line.strip()) for line in f]

# Function to write salt to file
def write_salt_to_file(salt):
    with open(user_salt_file, 'a') as f:
        f.write(base64.b64encode(salt).decode() + '\n')

# Function to read entropy from file
def read_entropy_from_file():
    with open(user_entropy_file, 'r') as f:
        return [line.strip() for line in f]

# Function to write entropy to file
def write_entropy_to_file(entropy):
    with open(user_entropy_file, 'a') as f:
        f.write(entropy + '\n')

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
    write_salt_to_file(salt)
    entropy=secrets.token_hex(8)
    write_entropy_to_file(entropy)
    
    password_bytes = (entropy+password).encode()
    

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
    salts = read_salts_from_file()
    entropies = read_entropy_from_file()

    salt = salts[position]
    entropy = entropies[position]
    print(salt)
    password_bytes = (entropy+password).encode()
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



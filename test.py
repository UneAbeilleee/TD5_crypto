from flask import Flask
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import tink
from tink import daead
from tink import core

import bcrypt
from tink.aead import aead_key_templates

core.Registry.register_key_manager(
    key_manager=tink.aead._aead_key_manager.AeadKeyManager.from_primitive(
        tink.aead.aead_key_templates.AES128_GCM
    ),
    new_key_allowed=True
)


app = Flask(__name__)

# Define key size and algorithm
key_size = 128
algorithm = "AES-GCM"

# Create a key template (using aead_key_templates)
key_template = aead_key_templates.AES128_GCM

# Generate a new KeysetHandle
keyset_handle = tink.new_keyset_handle(key_template)

# Generate a single Deterministic AEAD primitive
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)

password = 'a'
salt = b'\x8e\x8bh\xd0\x83d E]\x17}&\xb3\xb8\x84\x81'

# Convert password to bytes before hashing
password_bytes = password.encode()

# Hash the password using bcrypt
hashed_password = bcrypt.hashpw(password_bytes, salt)

# Encrypt deterministically with Tink
ciphertext = daead_primitive.encrypt_deterministically(password_bytes)
encrypted_password = base64.b64encode(ciphertext).decode('utf-8')

print(f'Hashed Password: {hashed_password}')
print(f'Encrypted Password: {encrypted_password}')

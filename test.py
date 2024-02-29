import flask
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import tink
from tink import daead
from tink import core

import bcrypt
from tink.aead import aead_key_templates

daead.register()

# Générer un nouveau KeysetHandle
keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)

# Générer un seul primitive AEAD déterministe
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)

password = 'a'

# Générer un sel valide en utilisant bcrypt.gensalt()
salt =b'$2b$12$Pq/MhNRjc//.ZESYqFtaBO'

# Convertir le mot de passe en octets avant le hachage
password_bytes = password.encode()

# Hacher le mot de passe en utilisant bcrypt avec le sel généré
hashed_password = bcrypt.hashpw(password_bytes, salt)

# Chiffrer de manière déterministe avec Tink
ciphertext = daead_primitive.encrypt_deterministically(password_bytes, b'')  # Fournir des données associées vides
encrypted_password = base64.b64encode(ciphertext).decode('utf-8')
print(keyset_handle)
print(f'Mot de passe haché : {hashed_password}')
print(f'Mot de passe chiffré : {encrypted_password}')


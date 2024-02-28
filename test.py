import secrets

# Generate a random 16-byte (128-bit) salt
salt = secrets.token_bytes(16)

print(salt)

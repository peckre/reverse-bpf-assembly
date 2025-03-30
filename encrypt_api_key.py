import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

# ====== Configuration ======
password = input("Enter encryption password: ").encode()
api_key = input("Enter your OpenAI API key: ").encode()
salt = os.urandom(16)  # Save this and embed it in your app
iterations = 100_000

# ====== Derive Fernet key ======
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=iterations,
    backend=default_backend()
)
fernet_key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(fernet_key)
encrypted_key = f.encrypt(api_key)

print(f"\n🔐 Encrypted API Key:\n{encrypted_key.decode()}")
print(f"\n🧂 Salt (base64):\n{base64.urlsafe_b64encode(salt).decode()}")

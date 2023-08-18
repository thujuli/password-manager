from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# password = "SECRET_KEY"
# salt = os.urandom(32)
# salt_base64 = base64.b64encode(salt).decode()
# kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
# key = base64.urlsafe_b64encode(kdf.derive(password.encode()))


# true_key = b"FJxHy4nqf1H_cHzyjplENOuwiRgJSul9RwxDR_paRGE="
salt_base64_str = "ucftW+zbEuJLlcrWTecKtFR+kcLEGb8XjrH2APDxDVk="
salt_base64 = salt_base64_str.encode()
salt = base64.b64decode(salt_base64)

password = "SECRET_KEY"
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

message = "secret_message"
f = Fernet(key)
token = f.encrypt(message.encode())

print(f, token, f.decrypt(token))

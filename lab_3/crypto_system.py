from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import json


def generate_keys(pub_path, priv_path, sym_path):
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = private_key.public_key()

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    



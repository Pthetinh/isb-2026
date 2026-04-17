from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def save_private_key(private_key: rsa.RSAPrivateKey, path: str) -> None:
    """Сохраните закрытый ключ RSA в файл в формате PEM."""

    with open(path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def save_public_key(public_key: rsa.RSAPublicKey, path: str) -> None:
    """Сохраните открытый ключ RSA в файл в формате PEM."""

    with open(path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key(path: str) -> None:
    """Загрузите закрытый ключ RSA из PEM-файла."""

    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    


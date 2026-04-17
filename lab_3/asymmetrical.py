from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Генерация пар ключей RSA для асимметричной криптографии."""

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_symmetric_key(sym_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Симметричное шифрование с использованием открытого ключа RSA."""
    
    encrypted_sym_key = public_key.encrypt(
        sym_key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )    
    )
    return encrypted_sym_key


def decrypt_symmetric_key(encrypted_sym_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Расшифруйте симметричный ключ, зашифрованный с помощью RSA."""
    
    sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return sym_key
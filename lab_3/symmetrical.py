import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import IDEA

def generate_symmetric_key(size: int = 16) -> bytes:
    """Сгенерируйте симметричный ключ для IDEA."""

    if(size != 16):
        raise ValueError("IDEA key size must be exactly 16 byte")
    return os.urandom(size)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Зашифруйте данные с помощью IDEA в режиме CBC."""
    
    iv = os.urandom(8)
    cipher = Cipher(IDEA(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(IDEA.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    c_text = encryptor.update(padded_data) + encryptor.finalize()

    return iv + c_text


def decrypt_data(data: bytes, key: bytes) -> bytes:
    """Расшифруйте данные, зашифрованные с помощью IDEA-CBC."""

    iv = data[:8]
    c_text = data[8:]

    cipher = Cipher(IDEA(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    dc_text = decryptor.update(c_text) + decryptor.finalize()

    unpadder = padding.PKCS7(IDEA.block_size).unpadder()
    unpadded_dc_text = unpadder.update(dc_text)  + unpadder.finalize()

    return unpadded_dc_text

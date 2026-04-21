from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Генерация пар ключей RSA для асимметричной криптографии.
    :return: закрытый ключ (RSAPrivateKey) и открытый ключ (RSAPublicKey)
    """

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )
    public_key = private_key.public_key()
    print('Сгенерированы ключи асимметричного шифрования')
    return private_key, public_key


def encrypt_sym_key(sym_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Симметричное шифрование с использованием открытого ключа RSA.
    :param sym_key: симметричный ключ для шифрования
    :param public_key: открытый ключ RSA
    :return: зашифрованный
    """
    
    encrypted_sym_key = public_key.encrypt(
        sym_key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )    
    )
    print('Ключ зашифрован алгоритмом асимметричного шифрования')
    return encrypted_sym_key


def decrypt_sym_key(encrypted_sym_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Расшифруйте симметричный ключ, зашифрованный с помощью RSA.
    :param encrypted_sym_key: зашифровванный симметричный ключ
    :param private_key: закрытый ключ RSA
    :return: расшифрованный ключ
    """
    
    sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('Ключ, зашифрованный алгоритмом асимметричного шифрования, расшифрован')
    return sym_key
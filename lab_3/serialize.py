from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def save_private_key(private_key: rsa.RSAPrivateKey, path: str) -> None:
    """
    Сохраните закрытый ключ RSA в файл в формате PEM.
    :param private_key: закрытый ключ RSA
    :param path: путь к выходному файлу
    :return: не возрашается
    """

    try:
        with open(path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    except OSError as e:
        print(f"Системная ошибка при записи файла {path} : {e}")

def save_public_key(public_key: rsa.RSAPublicKey, path: str) -> None:
    """
    Сохраните открытый ключ RSA в файл в формате PEM.
    :param public_key: открытый ключ RSA
    :param path: путь к выходному файлу
    :return: не возрашается
    """

    try:
        with open(path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    except OSError as e:
        print(f"Системная ошибка при записи файла {path} : {e}")


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    """
    Загрузите закрытый ключ RSA из PEM-файла.
    :param path: путь к файлу, содержащему закрытый ключ в формате PEM
    :return: загруженный закрытый ключ RSA
    """
    
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    except OSError as e:
        print(f"Системная ошибка при чтении файла {path} : {e}")

def save_binary(data: bytes, path: str) -> None:
    """
    Сохранить двоичные данные в файл.
    :param data: двоичные данные для сохранения
    :param path: путь к выходному файлу
    :return: не возврашается
    """
    
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        print(f"Системная ошибка при записи файла {path} : {e}")
    
def load_binary(path: str) -> bytes:
    """
    Прочитать двоичные данные из файла.
    :param path: Путь к файлу для чтения
    :return: двоичные данные, прочитанные из файла
    """
    
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        print(f"Системная ошибка при чтении файла {path} : {e}")
import hashlib
import os
import json 

DB_FILE = "users_db.json"

def load_db() -> dict:
    """
    Загружает базу данных пользователей из файла.
    :return: Словарь с данными пользователей.
    Если файл не существует, возвращает пустой словарь.
    """
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except OSError as e:
        print(f"Error reading database file: {e}")
        return {}

def save_db(db: dict) -> None:
    """
    Сохраняет базу данных пользователей в файл.
    :param db: Словарь с данными пользователей.
    :return: None
    """
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=4, ensure_ascii=False)
    except OSError as e:
        print(f"Error saving database: {e}")

def register_user_no_salt(username: str, password: str) -> None:
    """
    Регистрирует пользователя без использования соли.
    :param username: Имя пользователя.
    :param password: Пароль пользователя.
    :return: None
    """
    db = load_db()
    if username in db:
        raise ValueError("Username already exists!")
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db[username] = {"hash":hashed, "salt": None}
    save_db(db)

def login_user_no_salt(username: str, password: str) -> bool:
    """
    Авторизует пользователя без использования соли.
    :param username: Имя пользователя.
    :param password: Пароль пользователя.
    :return: True, если авторизация успешна, иначе False.
    """
    db = load_db()
    if username not in db:
        raise ValueError("Username does not exist!")
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    if db[username]["hash"] == hashed:
        return True
    return False

def register_user_with_salt(username: str, password: str) -> None:
    """
    Регистрирует пользователя с использованием соли.
    :param username: Имя пользователя.
    :param password: Пароль пользователя.
    :return: None
    """
    db = load_db()
    if username in db:
        raise ValueError("Username already exists!")
    
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()

    db[username] = {"hash":hashed, "salt": salt}
    save_db(db)

def login_user_with_salt(username: str, password: str) -> bool:
    """
    Авторизует пользователя с использованием соли.
    :param username: Имя пользователя.
    :param password: Пароль пользователя.
    :return: True, если авторизация успешна, иначе False.
    """
    db = load_db()
    if username not in db:
        raise ValueError("Username does not exist!")
    
    
    salt = db[username]["salt"]
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return db[username]["hash"] == hashed


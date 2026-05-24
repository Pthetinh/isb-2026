import pytest
import os
import auth_sys

def setup_fun() -> None:
    """
    Подготавливает тестовую среду.
    :return: None
    """
    if os.path.exits(auth_sys.DB_FILE):
        os.remove(auth_sys.DB_FILE)
    
def test_no_salt():
    """
    Тестирует регистрацию и авторизацию пользователя без использования соли.
    :return: None
    """
    auth_sys.register_user_no_salt("user", "passwd")

    assert auth_sys.login_user_no_salt("user", "passwd") == True      
    assert auth_sys.login_user_no_salt("user", "wrong") == False 

def test_with_salt():
    """
    Тестирует регистрацию и авторизацию пользователя с использованием соли.
    :return: None
    """
    auth_sys.register_user_with_salt("user_salt", "passwd_salt")

    assert auth_sys.login_user_with_salt("user_salt", "passwd_salt") == True

    db = auth_sys.load_db()
    assert db["user_salt"]["salt"] is not None

def test_user_exists():
    """
    Тестирует попытку регистрации существующего пользователя.
    :return: None
    """
    auth_sys.register_user_no_salt("existing", "pass")

    with pytest.raises(ValueError):
        auth_sys.register_user_no_salt("existing", "newpass")
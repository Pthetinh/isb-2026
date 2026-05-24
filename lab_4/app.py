import sys
import argparse
import time
import hashlib
from tqdm import tqdm
from PyQt5.QtWidgets import (
    QApplication, QHBoxLayout,
    QWidget, QVBoxLayout, 
    QLabel, QLineEdit, QPushButton, 
    QMessageBox, QTabWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPainter
import auth_sys as auth_system


def collision_simul(target_hash: str) -> int:
    """
    Имитация перебора для поиска хеш-кода
    с совпадающими первыми несколькими символами.
    :param target_hash: Целевой хеш-код, который нужно найти.
    :return: Число, которое при хешировании дает совпадение.
    """
    
    for i in tqdm (range(1000000), desc="Brute-forcing"):
        cur_hash = hashlib.sha256(str(i).encode()).hexdigest()
        if cur_hash.startswith(target_hash):
            print(f"\nCollision found: {i} -> {target_hash}")
            return i
        time.sleep(0.001)
    print("\nNo collision found in range.")

class AuthApp(QWidget):
    """
    Главное окно приложения для демонстрации регистрации и авторизации пользователей
    с использованием хеширования паролей с солью и без соли.
    Реализует пользовательский интерфейс для взаимодействия с системой аутентификации.
    """
    def __init__(self):
        """
        Инициализация приложения аутентификации.
        - Загрузка фонового изображения
        - Инициализация пользовательского интерфейса
        - Настройка основных компонентов
        """
        super().__init__()
        self.bg = QPixmap("./back-ground.jpg")
        self.initUi()
    
    def paintEvent(self, _):
        """Перерисовывает фоновое изображение, растягивая его на весь виджет."""
        painter = QPainter(self)
        painter.drawPixmap(self.rect(), self.bg)

    def initUi(self):
        """
        Инициализация пользовательского интерфейса приложения.
        Создание вкладок для регистрации и авторизации с солью и без соли
        Настройка стилей и расположения элементов интерфейса
        Подключение обработчиков событий для кнопок регистрации и авторизации
        """
        self.setWindowTitle("Lab 4 - Secure Password Hashing")
        self.resize(800, 600)
        
        layout = QVBoxLayout()
        self.tabs = QTabWidget()

        self.tab1 = QWidget()
        self.init_tab(self.tab1, with_salt=False)
        self.tabs.addTab(self.tab1, "No Salt")

        self.tab2 = QWidget()
        self.init_tab(self.tab2, with_salt=True)
        self.tabs.addTab(self.tab2, "With Salt")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def init_tab(self: 'AuthApp', tab: QWidget, with_salt: bool) -> None:
        """
        Инициализация вкладки для регистрации и авторизации.
        - Создание полей ввода для имени пользователя и пароля
        - Создание кнопок для регистрации и авторизации
        - Настройка стилей элементов интерфейса
        - Подключение обработчиков событий для кнопок
        :param tab: Виджет вкладки для инициализации
        :param with_salt: Флаг, указывающий, использовать ли соль для хеширования паролей
        :return: None
        """
        layout = QVBoxLayout()
        tab.setStyleSheet("""
            QLabel {
                color: #2c3e50;
                font-weight: bold;
            }
            QLineEdit {
                background-color: #ecf0f1;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 5px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        
        layout.setContentsMargins(100, 10, 100, 10)
        
        username_layout = QHBoxLayout()
        user_lbl = QLabel("Username:")
        user_input = QLineEdit()
        user_input.setPlaceholderText("Enter username...")
        username_layout.addWidget(user_lbl)
        username_layout.addWidget(user_input)

        password_layout = QHBoxLayout()
        pass_lbl = QLabel("Password:")
        pass_input = QLineEdit()
        pass_input.setPlaceholderText("Enter password...")
        pass_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(pass_lbl)
        password_layout.addWidget(pass_input)

        reg_btn = QPushButton("Register")
        login_btn = QPushButton("Login")

        reg_btn.setStyleSheet("background-color: #27ae60;")
        login_btn.setStyleSheet("background-color: #e74c3c;")

        layout.addLayout(username_layout)
        layout.addLayout(password_layout)
        layout.addWidget(login_btn)
        layout.addWidget(reg_btn)

        tab.setLayout(layout)

        def handle_reg()-> None:
            """
            Обработчик события для кнопки регистрации.
            :return: None
            """
            try:
                username = user_input.text()
                password = pass_input.text()
                if not username:
                    raise ValueError("Username cannot be empty!")
                if not password:
                    raise ValueError("Password cannot be empty!")
                if with_salt:
                    auth_system.register_user_with_salt(username, password)
                else:
                    auth_system.register_user_no_salt(username, password)
                QMessageBox.information(self, "Success", f"User {username} registered!")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

        def handle_login()-> None:
            """
            Обработчик события для кнопки авторизации.
            :return: None
            """
            try: 
                username = user_input.text()
                password = pass_input.text()
                if with_salt:
                    success = auth_system.login_user_with_salt(username, password)
                else:
                    success = auth_system.login_user_no_salt(username, password)    
                if success:
                    QMessageBox.information(self, "Success", "Login Successful!")
                else:
                    QMessageBox.warning(self, "Failed", "Invalid username or password!")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))     
                
        reg_btn.clicked.connect(handle_reg)
        login_btn.clicked.connect(handle_login)

def main()-> None:
    """
    Основная функция
    """
    parser = argparse.ArgumentParser(description="Lab 4: Hash Functions & Password Security")
    parser.add_argument('--mode', choices=['gui', 'cli', 'brute'], default='gui', help="Mode to run the app")
    parser.add_argument('--action', choices=['reg', 'login'], help="CLI action")
    parser.add_argument('-u', '--username', help="Username for CLI")
    parser.add_argument('-p', '--password', help="Password for CLI")
    parser.add_argument('--salted', action='store_true', help="Use salt for CLI actions")
    parser.add_argument('-t', "--target", default="0000", help="Target hash prefix for brute mode")


    args = parser.parse_args()
    
    
    match args.mode:
        case 'gui':
            app = QApplication(sys.argv)
            auth_app = AuthApp()
            auth_app.show() 
            sys.exit(app.exec_())
        case 'brute':
            print(f"Target prefix: {args.target}")
            print("Starting brute-force simulation...")
            collision_simul(args.target)
        case 'cli':
            if not args.action or not args.username or not args.password:
                print("Error: CLI mode requires --action, --username, and --password")
                return
            try:
                match args.action:
                    case 'reg':
                        if args.salted:
                            auth_system.register_user_with_salt(args.username, args.password)
                        else:
                            auth_system.register_user_no_salt(args.username, args.password) 
                        print(f"User {args.username} registered successfully!")
                    case 'login':
                        if args.salted:
                            success = auth_system.login_user_with_salt(args.username, args.password)        
                        else:
                            success = auth_system.login_user_no_salt(args.username, args.password)
                        print(f"Login result: {'Success' if success else 'Failed'}" )
                    case _:
                        print("Unknown action. Use 'reg' or 'login'.")    
            except Exception as e:
                print(f"Error: {e}")
        case _:
            print("Unknown mode. Use 'gui', 'cli', or 'brute'.")
if __name__ == '__main__':
    main()
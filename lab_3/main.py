from asymmetrical import (generate_rsa_keys, encrypt_sym_key, decrypt_sym_key)
from serialize import (save_private_key, save_public_key, load_private_key, load_binary, save_binary)
from symmetrical import (generate_symmetric_key, encrypt_data, decrypt_data)
import json
import os
import argparse

SETTING_FILE = 'Settings.json'

def load_settings(path: str) -> dict:
    """Считывание конфигурации из JSON-файла."""

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_parent_dir(path: str) -> None:
    """Обеспечить существование каталога для файла, 
    автоматически создать, если он не существует."""

    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)


def generate_mode(pub_path: str, priv_path: str, sym_path: str) -> None:
    """Генерация ключей для гибридной системы RSA + IDEA."""

    check_parent_dir(pub_path)
    check_parent_dir(priv_path)
    check_parent_dir(sym_path)

    prvivate_key, public_key = generate_rsa_keys()
    sym_key = generate_symmetric_key(16)
    encrypted_sym_key = encrypt_sym_key(sym_key, public_key)

    save_private_key(prvivate_key, priv_path)
    save_public_key(public_key, pub_path)
    save_binary(encrypted_sym_key, sym_path)

    print("Ключи успешно сгенерированы.")


def encrypt_mode(input_path: str, output_path: str, priv_path: str, sym_path: str) -> None:
    """Для шифрования файлов используется гибридное шифрование (RSA + IDEA)."""

    check_parent_dir(output_path)

    private_key = load_private_key(priv_path)
    encrypted_sym_key = load_binary(sym_path)
    sym_key = decrypt_sym_key(encrypted_sym_key, private_key)

    with open(input_path, "rb") as f:
        data = f.read()
    
    encrypted_data = encrypt_data(data, sym_key)
    save_binary(encrypted_data, output_path)

    print("Файл успешно зашифрован.")

def decrypt_mode(input_path: str, output_path: str, priv_path: str, sym_path: str) -> None:
    """Расшифровка файла, зашифрованного с использованием гибридного шифрования (RSA + IDEA)."""

    check_parent_dir(output_path)

    private_key = load_private_key(priv_path)
    encrypted_sym_key = load_binary(sym_path)
    sym_key = decrypt_sym_key(encrypted_sym_key, private_key)

    encrypted_data = load_binary(input_path)
    decrypted_data = decrypt_data(encrypted_data, sym_key)
    save_binary(decrypted_data, output_path)

    print("Файл успешно расшифрован.")


def main() -> None:
    """Основная функция"""

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Запускает режим дешифрования')

    group.add_argument('-set', '--settings', default=SETTING_FILE, type=str, help='Позволяет использовать собственный json-файл с указанием путей')

    args = parser.parse_args()
    settings =  load_settings(args.settings)

    try:
        public_key_path = settings["public_key"]
        private_key_path = settings["private_key"]
        sym_key_path = settings["sym_key"]
        input_enc_path = settings["input_file"]
        output_enc_path = settings["encrypted_file"]
        input_dec_path = settings["encrypted_file"]
        output_dec_path = settings["decrypted_file"]
    except KeyError as e:
        raise ValueError(f"В настройках отсутствует путь к файлу: {e}")
    
    match args:
        case args.generation:
            print("Режим генерации ключей начинается...")
            generate_mode(public_key_path, private_key_path, sym_key_path)
            return  
        
        case args.encryption:
            print("Режим шифрования начинается...")
            encrypt_mode(input_enc_path, output_enc_path, private_key_path, sym_key_path)
            return
        case args.decryption:
            print("Режим деширования начинается...")
            decrypt_mode(input_dec_path, output_dec_path, private_key_path, sym_key_path)

if __name__ == "__main__":
    main()
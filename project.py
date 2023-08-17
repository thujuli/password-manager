from pyfiglet import Figlet
from tabulate import tabulate
import hashlib
import os
import base64
import sys
import csv


class PasswordManager:
    def __init__(self) -> None:
        self._salt = ""
        self._key = ""

    @property
    def salt(self) -> str:
        return self._salt

    @property
    def key(self) -> str:
        return self._key

    def create_key(self, password: str) -> None:
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)

        # convert to str base64
        salt_base64_str = base64.b64encode(salt).decode()
        key_base64_str = base64.b64encode(key).decode()

        with open("master.key", "w", encoding="utf-8") as file:
            file.write(f"{salt_base64_str},{key_base64_str}")

    def verify_key(self, password: str) -> bool:
        with open("master.key", encoding="utf-8") as file:
            for row in file:
                self._salt, self._key = row.split(",")

        # encode salt to bytes
        salt_base64 = self._salt.encode()
        salt_bytes = base64.b64decode(salt_base64)

        # create new key
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000)

        # convert new_key to str base64
        new_key_base64_str = base64.b64encode(new_key).decode()

        return new_key_base64_str == self._key

    def create_password(
        self,
        site: str,
        username: str,
        password: str,
    ) -> None:
        if not os.path.exists("password.csv"):
            with open("password.csv") as csvfile:
                writer = csv.DictWriter(csvfile, ("site", "username", "password"))
                writer.writeheader()


def main() -> None:
    clear()
    pm = PasswordManager()
    banner("PM", "a password manager written in python.")

    try:
        if os.stat("master.key").st_size == 0 or not os.path.exists("master.key"):
            raise FileNotFoundError
    except FileNotFoundError:
        password = get_password()
        pm.create_key(password)

    mpass = input("Enter Master Key: ")

    if not pm.verify_key(mpass):
        sys.exit("Access Denied. Incorrect Master Key.")

    clear()
    menu_selected = menu()

    if menu_selected == "1":
        ...
    elif menu_selected == "2":
        while True:
            clear()
            banner("ENCRYPT", "encrypt the password and save to password.csv")
            credentials = get_user_credentials()

            print(
                tabulate(
                    [list(credentials.values())],
                    list(credentials.keys()),
                    tablefmt="grid",
                )
            )

        # pm.create_password(*credentials)
    elif menu_selected == "3":
        ...
    elif menu_selected == "4":
        ...
    else:
        sys.exit("Exiting...")


# def show_table(table: list[list], headers: list, tablefmt="grid"):
# print(tabulate(table, headers, tablefmt))


def get_user_credentials() -> dict:
    while True:
        try:
            site = input("Enter Site: ")
            username = input("Enter Username: ")
            password = input("Enter Password: ")
            confirm_password = input("Enter password (Confirmation): ")

            if password != confirm_password:
                print("Password Not Match!, Enter Again.\n")
                raise ValueError
            else:
                return {"site": site, "username": username, "password": password}
        except ValueError:
            pass


def menu() -> str:
    menus = ("1", "2", "3", "4", "5")

    print("\n1] List Password")
    print("2] Encrypt Password")
    print("3] Edit Password")
    print("4] Delete Password")
    print("5] Exit\n")

    while True:
        choice = input(">> ").strip()
        if choice in menus:
            return choice
        else:
            print("Invalid Choice. Try Again. [1/2/3/4/5]")


def clear() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def get_password() -> str:
    while True:
        password = input("Create Master Key: ")
        confirm_password = input("Create Master Key (Confirmation): ")

        try:
            if password != confirm_password:
                print("Password Not Match!, Enter Again.\n")
                raise ValueError
            else:
                print("Set A New Master Key.\n")
                return password
        except ValueError:
            pass


def banner(title: str, desc: str, style="drpepper", len_dec=50) -> None:
    f = Figlet(font=style)

    print("=" * len_dec)
    print("=" * len_dec)
    print(f.renderText(title), end="")
    print(desc.capitalize())
    print("=" * len_dec)
    print("=" * len_dec)


# def verify_key(password: str) -> bool:
#     salt = ""
#     key = ""
#
#     with open("master.key", encoding="utf-8") as file:
#         for row in file:
#             salt, key = row.split(",")
#
#     # encode salt to bytes
#     salt_base64 = salt.encode()
#     salt_bytes = base64.b64decode(salt_base64)
#
#     # create new key
#     new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000)
#
#     # convert new_key to str base64
#     new_key_base64_str = base64.b64encode(new_key).decode()
#
#     return new_key_base64_str == key


# def create_key(password: str) -> None:
#     salt = os.urandom(32)
#     key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
#
#     # convert to str base64
#     salt_base64_str = base64.b64encode(salt).decode()
#     key_base64_str = base64.b64encode(key).decode()
#
#     with open("master.key", "w", encoding="utf-8") as file:
#         file.write(f"{salt_base64_str},{key_base64_str}")


# User input
# password = "mysecretpassword"
# salt = os.urandom(16)  # Generate a random salt
#
# key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 10000, 32)

# Encode the derived key and salt as base64
# encoded_key = base64.b64encode(key).decode("utf-8")
# encoded_salt = base64.b64encode(salt).decode("utf-8")
#
# print("Encoded Key:", encoded_key)
# print("Key:", key)
# print("Encoded Salt:", encoded_salt)
# print("Salt:", salt)

if __name__ == "__main__":
    main()

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyfiglet import Figlet
from tabulate import tabulate
import os
import base64
import sys
import csv


def main() -> None:
    clear()
    banner("PM", "a password manager written in python.")

    try:
        if os.stat("master.key").st_size == 0 or not os.path.exists("master.key"):
            raise FileNotFoundError
    except FileNotFoundError:
        password = get_password()
        create_key(password)

    mkey = input("Enter Master Key: ")
    if not validation_key(mkey):
        sys.exit("Access Denied. Incorrect Master Key.")

    while True:
        clear()
        banner("MENU", "please select the available options.")
        menu_selected = menu()

        if menu_selected == "1":
            while True:
                clear()
                banner("LIST", "list all saved passwords")
                credentials = user_credentials()

                table = [list(x.values()) for x in credentials]
                headers = credentials[0].keys()
                print(
                    "",
                    tabulate(table, headers, tablefmt="grid"),
                    sep="\n",
                )

                back = input("\nEnter 'back' to go back.\n>> ").strip().lower()

                if back == "back":
                    break

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
                    ),
                    "",
                    sep="\n",
                )

                try:
                    sure = input("Are You Sure? [y/n] ").strip().lower()[0]
                    if sure == "y":
                        encrypt_password(**credentials)
                        break
                except IndexError:
                    pass

        elif menu_selected == "3":
            ...
        elif menu_selected == "4":
            clear()
            banner("DELETE", "delete password.")
            credentials = user_credentials()

            table = [list(x.values()) for x in credentials]
            headers = credentials[0].keys()
            print(
                tabulate(table, headers, tablefmt="grid"),
                sep="\n",
            )
            input()
        else:
            sys.exit("Exiting...")


def user_credentials() -> list[dict]:
    mkey_str = ""
    res = []

    try:
        with open("master.key", encoding="utf-8") as file:
            for row in file:
                _, mkey_str = row.split(",")
    except FileNotFoundError:
        sys.exit("Something went wrong.")

    try:
        with open("password.csv", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for i, row in enumerate(reader):
                f = Fernet(mkey_str.encode())
                token = row["password"]
                password = f.decrypt(token).decode()

                res.append(
                    {
                        "no": i + 1,
                        "site": row["site"],
                        "username": row["username"],
                        "password": password,
                    }
                )
    except FileNotFoundError:
        sys.exit("Something went wrong.")

    return res


def encrypt_password(site: str, username: str, password) -> None:
    mkey_str = ""

    try:
        with open("master.key", encoding="utf-8") as file:
            for row in file:
                _, mkey_str = row.split(",")
    except FileNotFoundError:
        sys.exit("Something went wrong.")

    f = Fernet(mkey_str.encode())
    token = f.encrypt(password.encode())

    try:
        if os.stat("password.csv").st_size == 0 or not os.path.exists("password.csv"):
            raise FileNotFoundError
    except FileNotFoundError:
        with open("password.csv", "w", encoding="utf-8") as csvfile:
            fieldnames = ("site", "username", "password")
            writer = csv.DictWriter(csvfile, fieldnames)
            writer.writeheader()

    with open("password.csv", "a", encoding="utf-8") as csvfile:
        fieldnames = ("site", "username", "password")
        writer = csv.DictWriter(csvfile, fieldnames)
        writer.writerow(
            {"site": site, "username": username, "password": token.decode()}
        )


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


def validation_key(password: str) -> bool:
    salt_base64_str = ""
    mkey_str = ""

    with open("master.key", encoding="utf-8") as file:
        for row in file:
            salt_base64_str, mkey_str = row.split(",")

    # encode salt to bytes
    salt_base64 = salt_base64_str.encode()
    salt = base64.b64decode(salt_base64)

    # create new key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    verify_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    return verify_key == mkey_str.encode()


def create_key(password: str) -> None:
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # convert to str base64
    salt_base64_str = base64.b64encode(salt).decode()
    key_str = key.decode()

    with open("master.key", "w", encoding="utf-8") as file:
        file.write(f"{salt_base64_str},{key_str}")


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


def clear() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


if __name__ == "__main__":
    main()

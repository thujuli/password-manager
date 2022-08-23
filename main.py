from cryptography.fernet import Fernet
from tabulate import tabulate

""""
    key = Fernet.generate_key()
    create = Fernet(key).encrypt("test123".encode())
    load = Fernet(key).decrypt(create).decode()
"""


class PasswordManager:
    def __init__(self):
        self.key = input("Input Key Path: ")
        self.path = input("Input Path to Read/Write Password: ")

    def create_key(self):
        with open(self.key, "wb") as f:
            f.write(Fernet.generate_key())

    def load_key(self):
        try:
            with open(self.key, "rb") as f:
                return f.read()
        except OSError:
            return "File not found!, Input correct KEY PATH"

    def generate_password(self, password):
        return Fernet(self.load_key()).encrypt(password.encode()).decode()

    def create_password(self):
        site = input("Input site: ")
        password = input("Input password: ")
        with open(self.path, "a") as f:
            f.write("{}:{}\n".format(site, self.generate_password(password)))

    def load_password(self, password):
        return Fernet(self.load_key()).decrypt(password.encode())

    def get_password(self):
        try:
            with open(self.path, "r") as f:
                lines = [line.strip().split(":") for line in f.readlines()]
                res = []
                for site, password in lines:
                    pass
                    res.append([site, self.load_password(password)])
                return tabulate(res)
        except OSError:
            return "File not found!, Input file Path where the password is saved!"


if __name__ == "__main__":
    user1 = PasswordManager()
    # user1.create_key()
    # print(user1.load_key())
    # user1.create_password()
    # print(user1.get_password())

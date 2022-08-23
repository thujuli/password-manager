from cryptography.fernet import Fernet
from tabulate import tabulate

""""
    key = Fernet.generate_key()
    create = Fernet(key).encrypt("test123".encode())
    load = Fernet(key).decrypt(create).decode()
"""


def create_key(key_path):
    with open(key_path, "wb") as f:
        f.write(Fernet.generate_key())


def load_key(key_path):
    with open(key_path, "rb") as f:
        return f.read()


def generate_password(key_path, password):
    key = load_key(key_path)
    return Fernet(key).encrypt(password.encode()).decode()


def create_password(key_path, passwd_path, site, password):
    with open(passwd_path, "a") as f:
        f.write("{}:{}\n".format(site, generate_password(key_path, password)))


def load_password(key_path, password):
    key = load_key(key_path)
    return Fernet(key).decrypt(password.encode()).decode()


def get_password(key_path, passwd_path):
    with open(passwd_path, "r") as f:
        lines = [line.strip().split(":") for line in f.readlines()]
        res = []
        for site, password in lines:
            res.append([site, load_password(key_path, password)])
        return res


if __name__ == "__main__":
    # create_key("thujuli.key")
    # print(load_key("thujuli.key"))
    # create_password("thujuli.key", "thujuli.pass", "github", "github@test")
    # print(tabulate(get_password("thujuli.key", "thujuli.pass")))
    pass

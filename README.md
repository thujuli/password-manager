# Password Manager

## Background

I have a problem with managing passwords:

1. Each site uses a different password.
2. I don't want to save my password in a file with the original password
3. If encrypt passwords, I want to have a master password with a key

Finally got idea after a few articles I read. The solution is a Password Manager with authentication using PBKDF2. In python, so many package for password encryption but i use crytography because this package easy for encrypt and decrypt.

## Requirements

- Python 3.5 or higher (I prefer use 3.10)

## Features

- Encrypt Password

![Encrypt Password](images/encrypt.png?raw=true "Encrypt Password")

- Display Password

![Display Password](images/list.png?raw=true "Display Password")

- Delete Password

![Delete Password](images/delete.png?raw=true "Delete Password")

- Edit Password

![Edit Password](images/edit.png?raw=true "Edit Password")

## Setup Project

- Clone this repository

```
# clone using ssh
git clone git@github.com:thujuli/password-manager.git

# clone using https
git clone https://github.com/thujuli/password-manager.git
```

## Running Project

- Create virtual environment

```
python -m venv venv
```

- Use the virtual environment

```
# linux or mac
source venv/bin/activate

# windows
venv\Scripts\activate
```

- Install third party packages from requirements.txt

```
pip install -r requirements.txt
```

- Run this project

```
python project.py
```

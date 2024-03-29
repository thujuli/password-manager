# Password Manager

![CS50P Certificate](images/CS50P.png?raw=true "CS50P Certificate")

#### Video Demo: [Password Manager](https://www.youtube.com/watch?v=yI3BWp-vnzc&t=3s)

### Background

I have a problem with managing passwords:

1. Each site uses a different password.
2. I don't want to save my password in a file with the original password
3. If encrypt passwords, I want to have a master password with a key

Finally got idea after a few articles I read. The solution is a Password Manager with authentication using PBKDF2. In python, so many package for password encryption but i use crytography because this package easy for encrypt and decrypt.

### Description:

This project is the development of a simple Password Manager created using the Python programming language. The Password Manager operates as a Command-Line Interface (CLI) application. Its primary purpose is to encrypt and securely store passwords entered by the user. The passwords are encrypted using the PBKDF2 algorithm before being saved in a CSV file.

### Key Features

1. **PBKDF2 Encryption:** User-entered passwords are encrypted using the PBKDF2 algorithm, enhancing security by generating a strong cryptographic hash.
2. **CSV Storage**: Encrypted passwords are stored in a CSV file. Each entry includes details such as the service name, username, and the encrypted password.
3. **CLI-Based Interaction:** The Password Manager operates through the command line, offering an interactive user experience for adding, deleting, and viewing stored passwords.
4. **Enhanced Display:** The application uses the `tabulate` library for formatted display of password information and `pyfiglet` for ASCII art headers

### Project Structure

- `project.py`: Main application file containing the Password Manager's logic.
- `test_project.py`: Test functions file to ensure the correct functionality of the Password Manager.
- `master.key`: File to store the encrypted master keyused by the user.This file is automatically generated after successfully authentication.
- `password.csv`: CSV file used for storing encrypted password data. This file is automatically generated after encrypting passwords.
- `README.md`: Documentation file containing project information, installation guide, and usage instructions.

### Installation

1. **Python 3.7:** Ensure Python 3.7 is installed on your system.
2. **Dependency Installation:** Navigate to the project directory and execute the following command to install required dependencies:

```
pip install -r requirements.txt
```

### Usage

1. **Running the Application:** Open a terminal and navigate to the project directory. Execute the following command to start the application:

```
python project.py
```

2. **Main Menu:**
   ![Main Menu](images/menu.png?raw=true "Main Menu")

3. **List Passwords:**
   ![Display Password](images/list.png?raw=true "Display Password")

4. **Encrypt Password:**
   ![Encrypt Password](images/encrypt.png?raw=true "Encrypt Password")

5. **Edit Password:**
   ![Edit Password](images/edit.png?raw=true "Edit Password")

6. **Delete Password:**
   ![Delete Password](images/delete.png?raw=true "Delete Password")

### Contributions

Community contributions are welcome. Create pull requests in the project's repository to contribute.

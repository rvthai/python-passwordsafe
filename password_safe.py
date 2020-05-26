from cryptography.fernet import Fernet 
from getpass import getpass
import sqlite3
import os


import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordSafe:
    def __init__(self, pin):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY , username text NOT NULL, password blob NOT NULL)')

        f = open('master.txt')
        user_data = f.readline()
        salt = bytes(user_data[2], 'utf-8')
        salt = base64.b64decode(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        self._key = base64.urlsafe_b64encode(kdf.derive(pin))
        

    def list_all(self):
        self._cursor.execute('SELECT title FROM entries')

        entries = self._cursor.fetchall()
        entries = [entry[0] for entry in entries]

        widest = len(max(entries, key=len)) + 4
        padded = [entry.ljust(widest) for entry in entries]

        colwidth = len(padded[0])
        width = os.get_terminal_size().columns
        #print(width)
        perline = ((width)-4) // colwidth 
        for i, pad in enumerate(padded):
            print(pad, end="")
            if i % perline == perline-1:
                print('\n', end='')
        print()

    def _decrypt(self, token):
        f = Fernet(self._key)
        password = f.decrypt(token)

        return password.decode("utf-8")

    def _encrypt(self, password):
        f = Fernet(self._key) 

        password = bytes(password, 'ascii')
        token = f.encrypt(password)

        return token

    def add(self, entry_name):
        print("Creating entry " + entry_name + "...")
        username = input("Username: ")

        password = getpass(prompt="Password: ")
        password_confirmation = getpass(prompt="Confirm Password: ")

        if password == password_confirmation: 

            encrypted_password = self._encrypt(password)

            params = (entry_name, username, encrypted_password)

            query = 'INSERT INTO entries (title, username, password) VALUES (?, ?, ?)'

            self._cursor.execute(query, params)

            self._connection.commit()
        else:
            print("Unable to add the entry. Passwords did not match.")

    def peek(self, entry_name):
        print("PEEK")

        params = (entry_name, )
        query = 'SELECT username, password FROM entries WHERE title = (?)'

        self._cursor.execute(query, params)

        entry = self._cursor.fetchone()

        decrypted_password = self._decrypt(entry[1])

        print(entry[0] + " ==> " + decrypted_password)

    def delete(self, entry_name):
        params = (entry_name, )
        query = 'DELETE FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        self._connection.commit()

    def edit(self, entry_name):
        pass

    def copy(self, entry_name):
        pass


import os
import sqlite3
from cryptography.fernet import Fernet 


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
        

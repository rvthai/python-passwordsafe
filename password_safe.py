import os
import sqlite3
from cryptography.fernet import Fernet 

class PasswordSafe:
    def __init__(self):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY , username text NOT NULL, password blob NOT NULL)')

    def add(self):
        print("ADD")

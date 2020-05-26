from cryptography.fernet import Fernet 
from getpass import getpass
import sqlite3
import os
import emoji


import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import pyperclip


class PasswordSafe:
    def __init__(self, key):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY , username text NOT NULL, password blob NOT NULL)')
        
        self._key = key
        

    def list_all(self):
        self._cursor.execute('SELECT title FROM entries')

        entries = self._cursor.fetchall()
        entries = [ entry[0] for entry in entries ]

        widest = len(max(entries, key=len)) + 4
        padded = [ entry.ljust(widest) for entry in entries ]
        colwidth = len(padded[0])
        width = os.get_terminal_size().columns
        
        perline = ((width) - 4) // colwidth

        print()
        for i, string in enumerate(padded):
            print(string, end='')
            if i % perline == perline - 1:
                print('\n', end='')
        print('\n')

    def _decrypt(self, token):
        f = Fernet(self._key)
        password = f.decrypt(token)

        return password.decode("utf-8")

    def _encrypt(self, password):
        f = Fernet(self._key) 

        password = bytes(password, 'ascii')
        token = f.encrypt(password)

        return token

    def _exists(self, entry_name):
        params = (entry_name, )
        query = 'SELECT title FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        if entry != None:
            return True 

        return False

    def add(self, entry_name):
        print("\nEnter a username and password to store for '" + entry_name + "'" )

        if self._exists(entry_name):
            #print("it already exists")
            return 

        username = input("Username: ")

        password = getpass(prompt="Password: ")
        password_confirmation = getpass(prompt="Confirm Password: ")

        if password == password_confirmation: 
            encrypted_password = self._encrypt(password)

            params = (entry_name, username, encrypted_password)
            query = 'INSERT INTO entries (title, username, password) VALUES (?, ?, ?)'

            self._cursor.execute(query, params)

            self._connection.commit()

            print("'" + entry_name + "' stored into safe.\n")
        else:
            print("\nUnable to add the entry. Passwords did not match.")

    def peek(self, entry_name):
        if not self._exists(entry_name):
            print("Does not exist.") 
            return 

        params = (entry_name, )
        query = 'SELECT username, password FROM entries WHERE title = (?)'

        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        decrypted_password = self._decrypt(entry[1])

        print('\n' + entry[0] + " ===> " + decrypted_password + '\n')

    def copy(self, entry_name):
        if not self._exists(entry_name):
            print("Does not exist.")
            return

        params = (entry_name, )
        query = 'SELECT password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone() 

        decrypted_password = self._decrypt(entry[0])
        pyperclip.copy(decrypted_password)

    def delete(self, entry_name):
        params = (entry_name, )
        query = 'DELETE FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        self._connection.commit()

    def edit(self, entry_name):
        if not self._exists(entry_name):
            print("Does not exist.")
            return 

        params = (entry_name, )
        query  = 'SELECT username, password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone() 

        username = input("Enter a new username[default enter if nothing changes]: ")
        if username == '':
            username = entry[0]
        password = getpass(prompt='Enter a new password [default enter if nothing changes]: ')
        if password == '':
            password = entry[1]
        else:
            password = self._encrypt(password)

        params = (username, password, entry_name)
        query = 'UPDATE entries SET username=(?), password=(?) WHERE title = (?)'
        self._cursor.execute(query, params)
        self._connection.commit() 

        print("UPDATED\n")

    def delete(self, entry_name):
        if not self._exists(entry_name):
            print("Does not exist.")
            return 

        confirm = input("Are you sure you want to delete blank? (yes or no): ")
        if confirm == 'y' or confirm == 'yes':
            params = (entry_name, )
            query = 'DELETE FROM entries WHERE title = (?)'
            self._cursor.execute(query, params)
            self._connection.commit() 
        else:
            return

        print("deleted\n")

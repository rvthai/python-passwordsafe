import os
from cryptography.fernet import Fernet 
from getpass import getpass
import sqlite3
import pyperclip



X = '\u2717'
LOCK_EMOJI = '\U0001F510'
CHECK_MARK = '\u2713'
DEFAULT_TEXT = '\x1b[0m'
ITALIC_TEXT = '\x1b[3m'
BOLD_TEXT = '\033[1m'
HEADER = '\033[95m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
DEFAULT_COLOR = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'

class PasswordSafe:
    def __init__(self, key):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY , username text NOT NULL, password blob NOT NULL)')
        
        self._key = key


    def add(self, entry_name):
        if self._exists(entry_name):
            print("\nEntry '" + entry_name + "' already exists.\n")
            return 

        print("\nEnter a username and password for entry '" + entry_name + "'." )

        username = input("Username: ")
        password = getpass(prompt="Password: ")
        password_confirmation = getpass(prompt="Confirm Password: ")

        if password == password_confirmation: 
            encrypted_password = self._encrypt(password)

            params = (entry_name, username, encrypted_password)
            query = 'INSERT INTO entries (title, username, password) VALUES (?, ?, ?)'

            self._cursor.execute(query, params)
            self._connection.commit()

            print(SUCCESS_COLOR + "Entry '" + entry_name + "' added.\n" + DEFAULT_COLOR)
        else:
            print(ERROR_COLOR + "Unable to add entry. Passwords did not match.\n" + DEFAULT_COLOR)


    def delete(self, entry_name):
        if not self._exists(entry_name):
            print("\nEntry '" + entry_name + "' does not exist.\n")
            return 

        confirmation = input("\nAre you sure you want to delete'" + entry_name + "' [Y/n]? ").strip().lower()
        if confirmation == 'y' or confirm == 'yes':
            params = (entry_name, )
            query = 'DELETE FROM entries WHERE title = (?)'
            self._cursor.execute(query, params)
            self._connection.commit() 

            print("Entry '" + entry_name + "' deleted.\n")

    def edit(self, entry_name):
        if not self._exists(entry_name):
            print("\nEntry '" + entry_name + "' does not exist.\n")
            return 

        params = (entry_name, )
        query  = 'SELECT username, password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        old_title = entry_name 
        old_username = entry[0] 
        old_password = self._decrypt(entry[1])

        print("\nEnter an updated title, username, and/or password for '" + entry_name + "'.")

        title = input("Title [" + old_title + "]: ")
        username = input("Username [" + old_username + "]: ")
        password = getpass(prompt="Password [" + old_password + "]: ")
        password_confirmation = getpass(prompt="Confirm Password [" + old_password + "]: ")

        if title.strip() == '':
            title = old_title

        if username.strip() == '':
            username = old_username
        
        if password == '' and password_confirmation == '':
            password = old_password

        if password_confirmation == '':
            password_confirmation = old_password

        if password == password_confirmation:
            password = self._encrypt(password)

            params = (title, username, password, entry_name)
            query = 'UPDATE entries SET title=(?), username=(?), password=(?) WHERE title = (?)'
            self._cursor.execute(query, params)
            self._connection.commit() 

            print(SUCCESS_COLOR + "Entry '" + entry_name + "' updated.\n" + DEFAULT_COLOR)
        else:
            print(ERROR_COLOR + "Unable to edit entry. Passwords did not match.\n" + DEFAULT_COLOR)


    def peek(self, entry_name):
        if not self._exists(entry_name):
            print("\nEntry '" + entry_name + "' does not exist.\n")
            return 

        params = (entry_name, )
        query = 'SELECT username, password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        decrypted_password = self._decrypt(entry[1])

        print('\n' + entry_name + " ==> " + entry[0] + " | " + decrypted_password + '\n')


    def copy(self, entry_name):
        if not self._exists(entry_name):
            print("\nEntry '" + entry_name + "' does not exist.\n")
            return

        params = (entry_name, )
        query = 'SELECT password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone() 

        decrypted_password = self._decrypt(entry[0])
        pyperclip.copy(decrypted_password)


    def list_all(self):
        #print(PURPLE + "Password Safe" + DEFAULT_COLOR)
        print("Password Safe")
        self._cursor.execute('SELECT title FROM entries')

        entries = self._cursor.fetchall()

        if len(entries) == 0:
            return 

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

    def close(self):
        self._connection.close()

    def _encrypt(self, password):
        f = Fernet(self._key) 

        password = bytes(password, 'ascii')
        token = f.encrypt(password)

        return token


    def _decrypt(self, token):
        f = Fernet(self._key)
        password = f.decrypt(token)

        return password.decode("utf-8")


    def _exists(self, entry_name):
        params = (entry_name, )
        query = 'SELECT title FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        if entry != None:
            return True 

        return False

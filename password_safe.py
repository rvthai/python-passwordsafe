import os
import sqlite3 
from cryptography.fernet import Fernet 
from getpass import getpass
import pyperclip


# Unicode text wrappers
ERROR_TEXT = '\033[91m\u2717 '
SUCCESS_TEXT = '\033[92m\u2713 '
HEADER_TEXT = '\033[94m\033[1m'
DEFAULT_TEXT = '\033[0m\x1b[0m'

class PasswordSafe:
    def __init__(self, key):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY, category text NOT NULL, username text NOT NULL, password blob NOT NULL)')
        
        self._key = key


    def add(self, entry_name):
        if self._exists(entry_name):
            print(ERROR_TEXT + "Entry '" + entry_name + "' already exists." + DEFAULT_TEXT)
            return 
        
        category = input("Group (e.g. personal, work, etc.): ").upper()
        username = input("Username: ")
        password = getpass(prompt = "Password: ")

        encrypted_password = self._encrypt(password)

        params = (entry_name, category, username, encrypted_password)
        query = 'INSERT INTO entries (title, category, username, password) VALUES (?, ?, ?, ?)'
        self._cursor.execute(query, params)
        self._connection.commit()

        print(SUCCESS_TEXT + "Success! Entry stored." + DEFAULT_TEXT)


    def delete(self, entry_name):
        if not self._exists(entry_name):
            print(ERROR_TEXT + "Entry '" + entry_name + "' not found." + DEFAULT_TEXT)
            return 

        confirmation = input("Are you sure you want to delete '" + entry_name + "'? [Y/n] ").strip().lower()
        if confirmation == 'y' or confirmation == 'yes':
            params = (entry_name, )
            query = 'DELETE FROM entries WHERE title = (?)'
            self._cursor.execute(query, params)
            self._connection.commit() 

            print(SUCCESS_TEXT + "Success! Entry deleted." + DEFAULT_TEXT)

    def edit(self, entry_name):
        if not self._exists(entry_name):
            print(ERROR_TEXT + "Entry '" + entry_name + "' not found." + DEFAULT_TEXT)
            return 

        params = (entry_name, )
        query  = 'SELECT category, username, password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        curr_title = entry_name
        curr_category = entry[0] 
        curr_username = entry[1] 
        curr_password = self._decrypt(entry[2])

        title = input("Title [" + curr_title + "]: ")
        category = input("Group [" + curr_category + "]: ").upper()
        username = input("Username [" + curr_username + "]: ")
        password = getpass(prompt = "Password [" + curr_password + "]: ")

        if title.strip() == '':
            title = curr_title
        if category.strip() == '':
            category = curr_category
        if username.strip() == '':
            username = curr_username
        if password == '':
            password = curr_password

        password = self._encrypt(password)

        params = (title, category, username, password, entry_name)
        query = 'UPDATE entries SET title=(?), category=(?), username=(?), password=(?) WHERE title = (?)'
        self._cursor.execute(query, params)
        self._connection.commit() 

        print(SUCCESS_TEXT + "Success! Entry updated." + DEFAULT_TEXT)


    def peek(self, entry_name):
        if not self._exists(entry_name):
            print(ERROR_TEXT + "Entry '" + entry_name + "' not found." + DEFAULT_TEXT)
            return 

        params = (entry_name, )
        query = 'SELECT username, password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        decrypted_password = self._decrypt(entry[1])

        print("Username ==> " + entry[0])
        print("Password ==> " + decrypted_password)


    def copy(self, entry_name):
        if not self._exists(entry_name):
            print(ERROR_TEXT + "Entry '" + entry_name + "' not found." + DEFAULT_TEXT)
            return

        params = (entry_name, )
        query = 'SELECT password FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone() 

        decrypted_password = self._decrypt(entry[0])

        pyperclip.copy(decrypted_password)


    def list_all(self):
        self._cursor.execute('SELECT category, title FROM entries')
        entries = self._cursor.fetchall()

        entries_count = len(entries)

        print("Password Safe (" + str(entries_count) + " entries)")

        if entries_count == 0:
            return 

        database = {}
        for category, entry in entries: 
            database.setdefault(category, []).append(entry) 

        self._display_tree(database)


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
        password = password.decode('utf-8')

        return password


    def _exists(self, entry_name):
        params = (entry_name, )
        query = 'SELECT title FROM entries WHERE title = (?)'
        self._cursor.execute(query, params)
        entry = self._cursor.fetchone()

        if entry != None:
            return True 

        return False


    def _display_tree(self, database):
        branch = '├─'
        pipe = '│'
        end = '└─'
        dash = '── '
        indent = ' ' * 5
        tab = ' ' * 4

        last_category = list(database.keys())[len(database.keys()) - 1]
        is_last_category = False

        for category in database.keys():
            if category == last_category:
                print(end + dash + HEADER_TEXT + category + DEFAULT_TEXT)
                is_last_category = True
            else:
                print(branch +  dash + HEADER_TEXT + category + DEFAULT_TEXT)

            last_entry = (database[category])[len(database[category]) - 1]
            for entry in database[category]:
                if entry == last_entry and is_last_category:
                    print(indent + end + dash + entry)
                elif entry == last_entry and not is_last_category:
                    print(pipe + tab + end + dash + entry)
                elif is_last_category:
                    print(indent + branch + dash + entry)
                else: 
                    print(pipe + tab + branch + dash + entry)
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

branch = '├─'
pipe = '│'
end = '└─'
dash = '─'
                  
child_conn_str = '│  '
leaf_inner_str = '├─ '
child_conn_str = '│  '
empty_str = '   '

class PasswordSafe:
    def __init__(self, key):
        self._connection = sqlite3.connect('password_safe.db')
        self._cursor = self._connection.cursor()

        self._cursor.execute('CREATE TABLE IF NOT EXISTS entries (title text NOT NULL PRIMARY KEY, category text NOT NULL, username text NOT NULL, password blob NOT NULL)')
        
        self._key = key


    def add(self, entry_name):
        if self._exists(entry_name):
            print("Entry '" + entry_name + "' already exists.")
            return 
        
        category = input("Group: ").upper()
        username = input("Username: ")
        password = getpass(prompt="Password: ")

        encrypted_password = self._encrypt(password)

        params = (entry_name, category, username, encrypted_password)
        query = 'INSERT INTO entries (title, category, username, password) VALUES (?, ?, ?, ?)'
        self._cursor.execute(query, params)
        self._connection.commit()

        print(GREEN + CHECK_MARK + " Success! Entry stored." + DEFAULT_COLOR)


    def delete(self, entry_name):
        if not self._exists(entry_name):
            print("Entry '" + entry_name + "' not found.")
            return 

        confirmation = input("Are you sure you want to delete '" + entry_name + "'? [Y/n] ").strip().lower()
        if confirmation == 'y' or confirmation == 'yes':
            params = (entry_name, )
            query = 'DELETE FROM entries WHERE title = (?)'
            self._cursor.execute(query, params)
            self._connection.commit() 

            print(GREEN + CHECK_MARK + " Success! Entry deleted." + DEFAULT_COLOR)

    def edit(self, entry_name):
        if not self._exists(entry_name):
            print("Entry '" + entry_name + "' not found.")
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
        password = getpass(prompt="Password [" + curr_password + "]: ")

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

        print(GREEN + CHECK_MARK + " Success! Entry updated." + DEFAULT_COLOR)


    def peek(self, entry_name):
        if not self._exists(entry_name):
            print("Entry '" + entry_name + "' not found.")
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
            print("Entry '" + entry_name + "' not found.")
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

        print("Password Safe (" + str(len(entries)) + " entries)")

        if len(entries) == 0:
            return 

        output = {}
        for a, b in entries: 
            output.setdefault(a, []).append(b) 

        lastone = None
        for k in output.keys():
            if list(output.keys()).index(k) == len(output.keys()) - 1:
                print(end + dash + dash + " " + BLUE + BOLD_TEXT + k + DEFAULT_TEXT+ DEFAULT_COLOR)
                lastone = True
            else:
                print(branch + dash + dash + " " + BLUE + BOLD_TEXT + k + DEFAULT_TEXT+ DEFAULT_COLOR)
            for v in output[k]:
                #print(output[k].index(v))
                if output[k].index(v) == len(output[k]) - 1 and lastone:
                    print("     " + end + dash + dash + " " + v)
                elif lastone:
                    print("     " + branch + dash + dash + " " + v)
                elif output[k].index(v) == len(output[k]) - 1:
                    print(pipe + "    " + end + dash + dash + " " + v)
                else: 
                    print(pipe + "    " + branch + dash + dash + " " + v)


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

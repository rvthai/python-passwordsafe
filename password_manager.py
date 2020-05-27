import os
import sys

import base64
import bcrypt
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from password_safe import PasswordSafe


X = '\u2717'
LOCK_EMOJI = '\U0001F510'
CHECK_MARK = '\u2713'
DEFAULT_TEXT = '\x1b[0m'
ITALIC_TEXT = '\x1b[3m'
BOLD_TEXT = '\033[1m'
HEADER = '\033[95m'
BLUE = '\033[94m'
PURPLE = '\033[94m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
DEFAULT_COLOR = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'

class PasswordManager:
    def __init__(self):
        self._password_safe = None

    def _destroy_safe(self):
        confirmation = input("Are you sure you want to destroy this safe? All data including the master PIN will be deleted. [Y/n] ").strip().lower()
        if confirmation == 'y' or confirmation == 'yes':
            os.remove('master.key')
            os.remove('password_safe.db')
            print(GREEN + CHECK_MARK + " Success! Password safe destroyed. Restart the program to set up a new safe." + DEFAULT_COLOR)
            sys.exit(0)


    def _display_options(self):
        print("add <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">     - Create and store an entry into the safe.")
        print("delete <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">  - Remove an entry from the safe.")
        print("edit <" +  ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Change and update the entry details.")
        print("peek <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Display the username and password of an entry.")
        print("copy <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Copy the password of an entry without peeking.")
        print("list            - View all the entries stored in the safe.")
        print("destroy         - Delete all data including the master PIN.")
        print("exit            - Lock the safe and exit the program.")


    def _manage_actions(self):
        print(CYAN + "\nUse the command 'help' for usage details\nUse the command 'exit' to exit at any time.\n" + DEFAULT_COLOR)

        cmd = ''
        
        while True:
            cmd = input(">> ").split(maxsplit = 1)

            if len(cmd) == 1:
                if cmd[0] == "help":
                    self._display_options()
                elif cmd[0] == "exit":
                    self._password_safe.close()
                    return
                elif cmd[0] == "list":
                    self._password_safe.list_all()
                elif cmd[0] == "destroy":
                    self._destroy_safe()
                elif cmd[0] in ("add", "delete", "edit", "peek", "copy"):
                    print("Command '" + cmd[0] + "' requires an additional parameter. Type 'help' for usage details.")
                else:
                    print("Command '" + cmd[0] + "' not found.")

            if len(cmd) == 2:
                if cmd[0] == "add":
                    self._password_safe.add(cmd[1])
                elif cmd[0] == "delete":
                    self._password_safe.delete(cmd[1])
                elif cmd[0] == "edit":
                    self._password_safe.edit(cmd[1])
                elif cmd[0] == "peek":
                    self._password_safe.peek(cmd[1])
                elif cmd[0] == "copy":
                    self._password_safe.copy(cmd[1])
                else:
                    print("Command '" + cmd[0] + "' not found.")

        return 


    def _auth_user(self):
        try: # clean this up bro
            f = open("master.key", 'br')
            hashed_pin = f.read()
        except FileNotFoundError:
            print("User data is not found.") 

        while True:
            pin = getpass(prompt="Enter your master PIN: ")
            pin = bytes(pin, 'ascii')

            if bcrypt.checkpw(pin, hashed_pin):
                break
            else:
                print(RED + X + " Incorrect PIN. Please try again." + DEFAULT_COLOR)

        key = self._derive_key(pin)
        self._password_safe = PasswordSafe(key)

        print(GREEN + CHECK_MARK + " Success! Password safe unlocked." + DEFAULT_COLOR)


    def _derive_key(self, pin):
        salt = b'V\x04<\x7f\x07\x89\xb1\xe5\x8dF\x02\xb2\x85\xb6\x9fw'

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        return base64.urlsafe_b64encode(kdf.derive(pin))


    def _store_pin(self, hashed_pin):
        try:
            f = open('master.key', 'wb')
            f.write(hashed_pin)
        except:
            print("error")
            sys.exit(0)
        finally:
            f.close()


    def _validate_pin(self, pin, pin_confirmation):
        # validate pin input is not blank
        if pin == '':
            print(X + " No PIN was entered.")
            return False 

        # validate pin is a combination of digits 0-9
        try:
            int(pin)
        except ValueError:
            print(X + " PIN was not a combination of digits 0-9.")
            return False 

        # validate pin is 4-digits long
        if len(pin) < 4:
            print(X + " PIN was less than 4-digits long.")
            return False 
        if len(pin) > 4: 
            print(X + " PIN was more than 4-digits long.")
            return False 

        # validate pins matched and were confirmed
        if pin != pin_confirmation:
            print(X + " The PIN numbers entered did not match.")
            return False

        return True
        
            
    def _create_user(self):
        print(CYAN + "Welcome! Let's get you set up. Create a master PIN and do not lose it! It is unrecoverable." + DEFAULT_COLOR)

        while True: 
            pin = getpass(prompt="Enter a 4-digit PIN: ") 
            pin_confirmation = getpass(prompt="Confirm your PIN: ")

            if self._validate_pin(pin, pin_confirmation):
                pin = bytes(pin, 'ascii')
                hashed_pin = bcrypt.hashpw(pin, bcrypt.gensalt())
                self._store_pin(hashed_pin)

                key = self._derive_key(pin)

                self._password_safe = PasswordSafe(key)

                print(GREEN + CHECK_MARK + " Success! Password safe configured. Restart the program and enter your master PIN to begin." + DEFAULT_COLOR)

                break
        
        return


    def _is_new_user(self):
        # Check to see if these user files already exist
        if os.path.exists("master.key") and os.path.exists("password_safe.db"):
            return False
        else:
            return True


    def _display_banner(self):
        print("\n===========================================================")
        print("\t" + BOLD_TEXT + LOCK_EMOJI + " PYTHON PASSWORD SAFE - Command Line Tool" + DEFAULT_TEXT)
        print("===========================================================\n")
    

    def run(self):
        self._display_banner()

        if self._is_new_user():
            self._create_user() 
        else:
            self._auth_user()
            self._manage_actions()
            

if __name__ == "__main__":
    try: 
        PasswordManager().run()
    except KeyboardInterrupt:
        print('\n')
        sys.exit(0)
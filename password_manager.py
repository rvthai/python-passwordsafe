import os
import sys

import base64
import bcrypt
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from password_safe import PasswordSafe

# Unicode text wrappers
LOCK_EMOJI = '\U0001F510'
ERROR_TEXT = '\033[91m\u2717 '
SUCCESS_TEXT = '\033[92m\u2713 '
INFO_TEXT = '\033[96m'
HEADER_TEXT = '\033[1m'
PARAM_TEXT = '\x1b[3m'
DEFAULT_TEXT = '\033[0m\x1b[0m'


class PasswordManager:
    def __init__(self):
        self._password_safe = None


    def _destroy_safe(self):
        confirmation = input("Are you sure you want to destroy this safe? All data including the master PIN will be deleted. [Y/n] ").strip().lower()

        if confirmation == 'y' or confirmation == 'yes':
            os.remove('master.key')
            os.remove('password_safe.db')

            print(SUCCESS_TEXT + "Success! Password safe destroyed. Restart the program to set up a new safe." + DEFAULT_TEXT)

            return True
        
        return False


    def _display_options(self):
        print("add <" + PARAM_TEXT + "entry" + DEFAULT_TEXT + ">     - Create and store an entry into the safe.")
        print("delete <" + PARAM_TEXT + "entry" + DEFAULT_TEXT + ">  - Remove an entry from the safe.")
        print("edit <" +  PARAM_TEXT + "entry" + DEFAULT_TEXT + ">    - Change and update an entry's information.")
        print("peek <" + PARAM_TEXT + "entry" + DEFAULT_TEXT + ">    - Display the username and password of an entry.")
        print("copy <" + PARAM_TEXT + "entry" + DEFAULT_TEXT + ">    - Copy the password of an entry without peeking.")
        print("list            - Display all the entries stored in the safe.")
        print("help            - Display available options and their usage details.")
        print("destroy         - Delete all data including the master PIN.")
        print("exit            - Lock the safe and exit the program.")


    def _manage_actions(self):
        print(INFO_TEXT + "\nUse the command 'help' for usage details\nUse the command 'exit' to exit at any time.\n" + DEFAULT_TEXT)

        cmd = ''
        
        while True:
            cmd = input(">> ").split(maxsplit = 1)

            if len(cmd) == 1:
                if cmd[0].lower() == 'help':
                    self._display_options()
                elif cmd[0].lower() == 'list':
                    self._password_safe.list_all()
                elif cmd[0].lower() == 'destroy':
                    if self._destroy_safe():
                        return
                elif cmd[0].lower() == 'exit':
                    self._password_safe.close()
                    return
                elif cmd[0].lower() in ('add', 'delete', 'edit', 'peek', 'copy'):
                    print(ERROR_TEXT + "Command '" + cmd[0].lower() + "' requires an additional parameter. Type 'help' for usage details." + DEFAULT_TEXT)
                else:
                    print(ERROR_TEXT + "Command '" + cmd[0] + "' not found." + DEFAULT_TEXT)

            if len(cmd) == 2:
                if cmd[0].lower() == 'add':
                    self._password_safe.add(cmd[1])
                elif cmd[0].lower() == 'delete':
                    self._password_safe.delete(cmd[1])
                elif cmd[0].lower() == 'edit':
                    self._password_safe.edit(cmd[1])
                elif cmd[0].lower() == 'peek':
                    self._password_safe.peek(cmd[1])
                elif cmd[0].lower() == 'copy':
                    self._password_safe.copy(cmd[1])
                else:
                    print(ERROR_TEXT + "Command '" + cmd[0] + "' not found." + DEFAULT_TEXT)


    def _derive_key(self, pin):
        salt = b'V\x04<\x7f\x07\x89\xb1\xe5\x8dF\x02\xb2\x85\xb6\x9fw'

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 100000,
            backend = default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(pin))

        return key


    def _auth_user(self):
        try:
            f = open('master.key', 'br')
            hashed_pin = f.read()
        except FileNotFoundError:
            print(ERROR_TEXT + "User data is corrupted or lost. Unable to authroize user." + DEFAULT_TEXT) 

        while True:
            pin = getpass(prompt = "Enter your master PIN: ")
            pin = bytes(pin, 'ascii')

            if bcrypt.checkpw(pin, hashed_pin):
                key = self._derive_key(pin)
                self._password_safe = PasswordSafe(key)

                print(SUCCESS_TEXT + "Success! Password safe unlocked." + DEFAULT_TEXT)
                return
            else:
                print(ERROR_TEXT + "Incorrect PIN. Please try again." + DEFAULT_TEXT)


    def _validate_pin(self, pin, pin_confirmation):
        # validate that input is not blank
        if pin == '':
            print(ERROR_TEXT + "No PIN was entered. Please try again." + DEFAULT_TEXT)
            return False 

        # validate that pin is a combination of digits 0-9
        try:
            int(pin)
        except ValueError:
            print(ERROR_TEXT + "PIN was not a combination of digits 0-9. Please try again." + DEFAULT_TEXT)
            return False 

        # validate that pin is 4-digits long
        if len(pin) != 4:
            print(ERROR_TEXT + "PIN must be 4-digits long. Please try again." + DEFAULT_TEXT)
            return False 

        # validate that pin was confirmed
        if pin != pin_confirmation:
            print(ERROR_TEXT + "The PIN numbers entered did not match. Please try again." + DEFAULT_TEXT)
            return False

        return True
        
            
    def _create_user(self):
        print(INFO_TEXT + "Welcome! To get started, create a master PIN. Do not lose it as it is unrecoverable." + DEFAULT_TEXT)

        while True: 
            pin = getpass(prompt = "Enter a 4-digit PIN: ") 
            pin_confirmation = getpass(prompt = "Confirm your PIN: ")

            if self._validate_pin(pin, pin_confirmation):
                pin = bytes(pin, 'ascii')
                hashed_pin = bcrypt.hashpw(pin, bcrypt.gensalt())

                f = open('master.key', 'wb')
                f.write(hashed_pin)
                f.close()

                key = self._derive_key(pin)
                self._password_safe = PasswordSafe(key)

                print(SUCCESS_TEXT + "Success! Password safe configured. Restart the program and enter your master PIN to begin." + DEFAULT_TEXT)
                
                return


    def _is_new_user(self):
        if os.path.exists('master.key') and os.path.exists('password_safe.db'):
            return False
        return True


    def _display_banner(self):
        print("\n===========================================================")
        print("\t" + HEADER_TEXT + LOCK_EMOJI + " PYTHON PASSWORD SAFE - Command Line Tool" + DEFAULT_TEXT)
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
        print("\n")
        sys.exit(0)
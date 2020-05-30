import os
import sys

import base64
import bcrypt
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .password_safe import PasswordSafe
from .text_wrappers import TextWrappers


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class PasswordManager:
    def __init__(self):
        self._password_safe = None
        self._text = TextWrappers()

    def _destroy_safe(self):
        confirmation = input("Are you sure you want to destroy this safe? All data including the master PIN will be deleted. [Y/n] ").strip().lower()

        self._password_safe.close()

        if confirmation == 'y' or confirmation == 'yes':
            os.remove(ROOT_DIR + '/master.key')
            os.remove(ROOT_DIR + '/password_safe.db')

            print(self._text.SUCCESS + "Success! Password safe destroyed. Restart the program to set up a new safe." + self._text.DEFAULT)

            return True
        
        return False


    def _display_options(self):
        print("add <" + self._text.PARAM + "entry" + self._text.DEFAULT + ">        - Create and store an entry into the safe.")
        print("delete <" + self._text.PARAM + "entry" + self._text.DEFAULT + ">     - Remove an entry from the safe.")
        print("edit <" +  self._text.PARAM + "entry" + self._text.DEFAULT + ">       - Change and update an entry's information.")
        print("peek <" + self._text.PARAM + "entry" + self._text.DEFAULT + ">       - Display the username and password of an entry.")
        print("copy <" + self._text.PARAM + "entry" + self._text.DEFAULT + ">       - Copy the password of an entry without peeking.")
        print("list               - Display all the entries stored in the safe.")
        print("help               - Display available options and their usage details.")
        print("destroy            - Delete all data including the master PIN.")
        print("exit               - Lock the safe and exit the program.")


    def _manage_actions(self):
        print(self._text.INFO + "\nUse the command 'help' for usage details\nUse the command 'exit' to exit at any time.\n" + self._text.DEFAULT)

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
                    print(self._text.ERROR + "Command '" + cmd[0].lower() + "' requires an additional parameter. Type 'help' for usage details." + self._text.DEFAULT)
                else:
                    print(self._text.ERROR + "Command '" + cmd[0] + "' not found." + self._text.DEFAULT)

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
                    print(self._text.ERROR + "Command '" + cmd[0] + "' not found." + self._text.DEFAULT)


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
            f = open(ROOT_DIR + '/master.key', 'br')
            hashed_pin = f.read()
        except FileNotFoundError:
            print(self._text.ERROR + "User data is corrupted or lost. Unable to authroize user." + self._text.DEFAULT) 

        while True:
            pin = getpass(prompt = "Enter your master PIN: ")
            pin = bytes(pin, 'ascii')

            if bcrypt.checkpw(pin, hashed_pin):
                key = self._derive_key(pin)
                self._password_safe = PasswordSafe(key)

                print(self._text.SUCCESS + "Success! Password safe unlocked." + self._text.DEFAULT)
                return
            else:
                print(self._text.ERROR + "Incorrect PIN. Please try again." + self._text.DEFAULT)


    def _validate_pin(self, pin, pin_confirmation):
        # validate that input is not blank
        if pin == '':
            print(self._text.ERROR + "No PIN was entered. Please try again." + self._text.DEFAULT)
            return False 

        # validate that pin is a combination of digits 0-9
        try:
            int(pin)
        except ValueError:
            print(self._text.ERROR + "PIN was not a combination of digits 0-9. Please try again." + self._text.DEFAULT)
            return False 

        # validate that pin is 4-digits long
        if len(pin) != 4:
            print(self._text.ERROR + "PIN must be 4-digits long. Please try again." + self._text.DEFAULT)
            return False 

        # validate that pin was confirmed
        if pin != pin_confirmation:
            print(self._text.ERROR + "The PIN numbers entered did not match. Please try again." + self._text.DEFAULT)
            return False

        return True
        
            
    def _create_user(self):
        print(self._text.INFO + "Welcome! To get started, create a master PIN. Do not lose it as it is unrecoverable." + self._text.DEFAULT)

        while True: 
            pin = getpass(prompt = "Enter a 4-digit PIN: ") 
            pin_confirmation = getpass(prompt = "Confirm your PIN: ")

            if self._validate_pin(pin, pin_confirmation):
                pin = bytes(pin, 'ascii')
                hashed_pin = bcrypt.hashpw(pin, bcrypt.gensalt())

                f = open(ROOT_DIR + '/master.key', 'wb')
                f.write(hashed_pin)
                f.close()

                key = self._derive_key(pin)
                self._password_safe = PasswordSafe(key)

                print(self._text.SUCCESS + "Success! Password safe configured. Restart the program and enter your master PIN to begin." + self._text.DEFAULT)
                
                return


    def _is_new_user(self):
        if os.path.exists(ROOT_DIR + '/master.key') and os.path.exists(ROOT_DIR + '/password_safe.db'):
            return False
        return True


    def _display_banner(self):
        print("\n===========================================================")
        print("\t" + self._text.BANNER + self._text.LOCK + "PYTHON PASSWORD SAFE - Command Line Tool" + self._text.DEFAULT)
        print("===========================================================\n")
    

    def run(self):
        self._display_banner()

        if self._is_new_user():
            self._create_user() 
        else:
            self._auth_user()
            self._manage_actions()

def main():
    try: 
        PasswordManager().run()
    except KeyboardInterrupt:
        print("\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import emoji

import base64
import bcrypt
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from password_safe import PasswordSafe



DEFAULT_TEXT = '\x1b[0m'
ITALIC_TEXT = '\x1b[3m'

class PasswordManager:
    def __init__(self):
        self._password_safe = None


    def _display_options(self):
        print("\nadd <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">     - Create and store an entry into the safe.")
        print("delete <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">  - Remove an entry from the safe.")
        print("edit <" +  ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Change and update the entry details.")
        print("peek <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Display the username and password of an entry.")
        print("copy <" + ITALIC_TEXT + "entry" + DEFAULT_TEXT + ">    - Copy the password of an entry without peeking.")
        print("list            - View all the entries stored in the safe.")
        print("exit            - Lock the safe and exit the application.\n")


    def _manage_actions(self):
        cmd = ''
        
        while True:
            cmd = input(">> ").split(maxsplit = 1)

            if len(cmd) == 1:
                if cmd[0] == "exit":
                    self._password_safe.close()
                    return
                elif cmd[0] == "list":
                    self._password_safe.list_all()
                elif cmd[0] == "help":
                    self._display_options()
                elif cmd[0] in ("add", "delete", "edit", "peek", "copy"):
                    print("\nCommand '" + cmd[0] + "' requires an additional parameter. Type 'help' for usage details.\n")
                else:
                    print("\nCommand not found: '" + cmd[0] + "'\n")

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
                    print("\nCommand not found'" + cmd[0] + " " + cmd[1] + "'\n")

        return 


    def _auth_user(self):
        print(emoji.emojize(":locked:") + " Enter your PIN to unlock the password safe.\n")

        try:
            f = open("master.key", 'br')
            hashed_pin = f.read()
        except FileNotFoundError:
            print(error_msg + " User data is not found.") 

        while True:
            pin = getpass(prompt="PIN: ")
            pin = bytes(pin, 'ascii')

            if bcrypt.checkpw(pin, hashed_pin):
                break
            else:
                print("The PIN you entered is incorrect. Please try again.")

        key = self._derive_key(pin)
        self._password_safe = PasswordSafe(key)

        print('\n' + emoji.emojize(":unlocked:") + " Password safe successfully unlocked.")
        print("\n-----------------------------------------------------------\n")
        print(emoji.emojize(":information:") + " Use the command 'help' for usage details.\n")


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
        error_msg = "\nUnable to configure your safe."

        # validate pin input is not blank
        if pin == '':
            print(error_msg + " No PIN was entered.")
            return False 

        # validate pin is a combination of digits 0-9
        try:
            int(pin)
        except ValueError:
            print(error_msg + " PIN was not a combination of digits 0-9.")
            return False 

        # validate pin is 4-digits long
        if len(pin) < 4:
            print(error_msg + " PIN was less than 4-digits long.")
            return False 
        if len(pin) > 4: 
            print(error_msg + " PIN was more than 4-digits long.")
            return False 

        # validate pins matched and were confirmed
        if pin != pin_confirmation:
            print(error_msg + " The PIN numbers entered did not match.")
            return False

        return True
        
            
    def _create_user(self):
        print(emoji.emojize(":waving_hand:") + " Welcome! Let's get you set up...\n")

        pin = getpass(prompt="Enter a 4-digit PIN: ") 
        pin_confirmation = getpass(prompt="Confirm PIN: ")

        if self._validate_pin(pin, pin_confirmation):
            pin = bytes(pin, 'ascii')
            hashed_pin = bcrypt.hashpw(pin, bcrypt.gensalt())
            self._store_pin(hashed_pin)

            key = self._derive_key(pin)

            self._password_safe = PasswordSafe(key)

            print("\n" + emoji.emojize(":white_heavy_check_mark:") + " Password safe successfully configured.")
            print("\n-----------------------------------------------------------\n")
        else:
            print("Please try again later.\n")
            sys.exit(0)


    def _is_new_user(self):
        # Check to see if these user files already exist
        if os.path.exists("master.key") and os.path.exists("password_safe.db"):
            return False
        else:
            return True


    def _display_banner(self):
        print("\n===========================================================\n")
        print("\t" + emoji.emojize(":locked_with_key:") + " PYTHON PASSWORD SAFE - Command Line Tool")
        print("\n===========================================================\n")
    

    def run(self):
        self._display_banner()

        if self._is_new_user():
            self._create_user() 
        
        self._auth_user()

        self._manage_actions()
            

if __name__ == "__main__":
    try: 
        PasswordManager().run()
    except KeyboardInterrupt:
        print('\n')
        sys.exit(0)
from getpass import getpass
import bcrypt
import base64 
import sys
import os
import emoji

from password_safe import PasswordSafe 

class PasswordManager:
    def __init__(self):
        self._password_safe = None

    def _parse_cmd(self, cmd):
        if len(cmd) > 2:
            print("command not found")

        if len(cmd) == 1:
            if cmd[0] == "exit":
                print("Goodbye")
            elif cmd[0] == "list":
                self._password_safe.list_all()

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
                print("Command not found")

    def _manage_user_actions(self):
        cmd = ''
        
        while True:
            cmd = input("> ").lower().split(maxsplit=1)
            self._parse_cmd(cmd)

        return 

    def _auth_user(self):
        error_msg = "\n" + emoji.emojize(':cross_mark:') + " Unable to authorize user."

        try:
            f = open("master.txt", 'r')

            user_data = f.readline().split()
            name = user_data[0]
            hashed_pin = bytes(user_data[1], 'ascii')

            print("\n" + emoji.emojize(":waving_hand:") + " Hello, " + name + "! Please enter your PIN...\n")

            pin = getpass(prompt="   PIN: ")
            pin = bytes(pin, 'ascii')

            # Connect to the database if PINs match
            if bcrypt.checkpw(pin, hashed_pin):
                self._password_safe = PasswordSafe(pin)
                print('\n' + emoji.emojize(":unlocked:") + " Password safe has been successfully unlocked.")
                print("   Use the command 'help' for usage details.\n")
            else:
                print(error_msg + " Incorrect PIN.")
                sys.exit(0)
        except FileNotFoundError:
            print(error_msg + " User data is not found.") 

    def _validate_fields(self, name, pin, pin_confirmation):
        error_msg = "\n" + emoji.emojize(':cross_mark:') + " Unable to configure your safe."

        # validate name input is not blank
        if name == '':
            print(error_msg + " No name was entered.\n")
            return False 

        # validate pin input is not blank
        if pin == '':
            print(error_msg + " No PIN was entered.\n")
            return False 

        # validate pin is a combination of digits 0-9
        try:
            int(pin)
        except ValueError:
            print(error_msg + " PIN was not a combination of digits 0-9.\n")
            return False 

        # validate pin is 4-digits long
        if len(pin) < 4:
            print(error_msg + " PIN was less than 4-digits long.\n")
            return False 
        if len(pin) > 4: 
            print(error_msg + " PIN was more than 4-digits long.\n")
            return False 

        # validate pins matched and were confirmed
        if pin != pin_confirmation:
            print(error_msg + " The PIN numbers entered did not match.\n")
            return False

        return True
        
            
    def _create_user(self):
        print(emoji.emojize(":waving_hand:") + " Welcome! Let's get you set up...\n")

        name = input("   Enter your name: ").strip()
        pin = getpass(prompt="   Enter a 4-digit PIN: ") 
        pin_confirmation = getpass(prompt="   Confirm your PIN: ")

        # Validate user inputs before continuing.
        if self._validate_fields(name, pin, pin_confirmation):

            # Hash the PIN number with a random generated salt and store it in the database.
            pin = bytes(pin, 'ascii')
            hashed_pin = bcrypt.hashpw(pin, bcrypt.gensalt())

            # Create an encryption key for the passwords that will be stored in the safe.
            key = os.urandom(16)
            #print(key, type(key))
            #print()

            key = base64.b64encode(key).decode('utf-8')
            #print(key, type(key))
            #key = bytes(key, 'utf-8')
            #print(key, type(key))
            #key = base64.b64decode(key)  
            #print(key, type(key))
            #key = b64encode(key).decode('utf-8')
            #print(type(key))

            #key = bytes(b64encode(key))
            #print(type(key))
            #key = bytes(key)
            #print(key)
            #sys.exit(0)

            try: 
                f = open('master.txt', 'w')
                data = name + " " + hashed_pin.decode('utf-8') + " " + key
                f.write(data)
                f.close()
            except:
                print("Unable to do something with file") # need better error message here #####

            # Create the database file through the password safe object.
            self._password_safe = PasswordSafe()
            # then close it after creating it

            print("\n" + emoji.emojize(":white_heavy_check_mark:") + " Success! Your password safe has been configured.")
        else:
            sys.exit(0)
            
    def _is_new_user(self):
        # If these files already exists, then there is already a password
        # safe configured and the user is a returning user.
        if os.path.exists("master.txt") and os.path.exists("password_safe.db"):
            return False
        else:
            return True

    def _display_banner(self):
        print("\n===========================================================\n")
        print("\t" + emoji.emojize(":locked_with_key:") + " PYTHON PASSWORD SAFE - Command Line Tool")
        print("\n===========================================================\n")
    
    def run(self):
        self._display_banner()

        # Create user data if user is new and using the program for the first time.
        if self._is_new_user():
            self._create_user() 
        
        # Authorize the user before connecting to the database.
        self._auth_user()

        self._manage_user_actions()

        print("Goodbye")
            

if __name__ == "__main__":
    try: 
        PasswordManager().run()
    except KeyboardInterrupt:
        sys.exit(0)
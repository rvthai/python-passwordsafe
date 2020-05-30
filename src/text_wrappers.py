import sys 

class TextWrappers:
    def __init__(self):
        if (sys.platform == 'win32'):
            self.LOCK = ''
            self.ERROR = ''
            self.SUCCESS = ''
            self.INFO = ''
            self.BANNER = ''
            self.PARAM = ''
            self.DEFAULT = ''
            self.HEADER = ''
            self.DEFAULT = ''
        else: # MacOS, Linux, etc.
            self.LOCK = '\U0001F510 '
            self.ERROR = '\033[91m\u2717 '
            self.SUCCESS = '\033[92m\u2713 '
            self.INFO = '\033[96m'
            self.BANNER = '\033[1m'
            self.PARAM = '\x1b[3m'
            self.DEFAULT = '\033[0m\x1b[0m'
            self.HEADER = '\033[94m\033[1m'
            self.DEFAULT = '\033[0m\x1b[0m'
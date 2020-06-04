import setuptools 

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup (
    name = 'py-pwsafe',
    version = '2.0.3',
    description = 'Python Password Safe',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    author = 'Ricky Thai',
    author_email = 'rickyvanthai@gmail.com',
    url = 'https://github.com/rvthai/python-passwordsafe',
    package_dir={'pypwsafe': 'src'},
    packages = ['pypwsafe'],
    install_requires=['bcrypt', 'pyperclip', 'cryptography'],  
    entry_points = {
        'console_scripts': ['pypwsafe = pypwsafe.password_manager:main'],
    },
    license = 'MIT',
    classifiers = [
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires = '>=3.6'
)
import json
import subprocess
import sqlite3

from getpass import getuser

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


# loginData = 'LoginData'
LOGIN_DATA = f'/Users/{getuser()}/Library/Application Support/Google/Chrome/Default/Cookies'

# Default values used by both Chrome and Chromium in OSX and Linux
IV = b' ' * 16
SALT = b'saltysalt'
LENGTH = 16
ITERATIONS = 1003


def clean(s):
    if s:
        s = s[:-s[-1]].decode('utf8').strip()
    return s


def get_encryption_key():
    """Decryption pass for Crome Mac OS"""

    cmd = "security find-generic-password -wa 'Chrome'"

    storage_key = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )
    stdout, _ = storage_key.communicate()
    storage_key = stdout.replace(b'\n', b'')

    return storage_key


def decrypt_chrome_data(encrypted_value, encrypted_key):
    # Trim off the 'v10' that Chrome/ium prepends
    encrypted_value = encrypted_value[3:]
    encrypted_key = PBKDF2(
        password=encrypted_key, 
        salt=SALT, 
        dkLen=LENGTH, 
        count=ITERATIONS
    )

    try:
        cipher = AES.new(IV=IV, mode=AES.MODE_CBC, key=encrypted_key)
        decrypted_value = cipher.decrypt(encrypted_value)
    except Exception as e:
        decrypted_value = f'ERROR: {e}'

    return decrypted_value
    


def get_chrome_cookies():

    database = sqlite3.connect(LOGIN_DATA)
    sql = 'select host_key, name, encrypted_value, path from cookies'
    encryption_key = get_encryption_key()
    
    cookies = []

    with open('cookies.json', 'w') as file:
        with database:
            for host_key, name, encrypted_value, path in database.execute(sql):

                value_decrypted = decrypt_chrome_data(encrypted_value, encryption_key)
                value = str(clean(value_decrypted))

                cookie_json = {
                    'domain': host_key,
                    'path': path,
                    'name': name,
                    'value': value
                }
                cookies.append(cookie_json)
                    
        file.write(str(json.dumps(cookies)))

get_chrome_cookies()

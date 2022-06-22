import json
import sys
import getpass
import re
import time
from Crypto.Hash import SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def check_password_complexity(password):
    while True:
        if len(password) < 8:
            flag = -1
            break
        elif not re.search("[a-z]", password):
            flag = -1
            break
        elif not re.search("[A-Z]", password):
            flag = -1
            break
        elif not re.search("[0-9]", password):
            flag = -1
            break
        else:
            return True

    if flag == -1:
        return False

def createString(user, hash_password, separator, flag, salt):
    string = ""
    string = user + separator + hash_password.hex() + separator + salt.hex() + separator + flag
    return string

#main
separator = "--"
user = sys.argv[1]
f = open("data.txt", "r+")
data = []
users = []
for each in f:
    each = each.replace("\n", "")
    data.append(each)
    users.append(each.split("--")[0])

for each in data:
    if each.split("--")[0] == user:
        tmp_salt = each.split("--")[2]
        tmp_pass = each.split("--")[1]
        change_pass = each.split("--")[3]

password = getpass.getpass("Password:")
hash1 = PBKDF2(password, bytes.fromhex(tmp_salt), 64, count=1000000, hmac_hash_module=SHA512).hex()
counter = 0

while tmp_pass != hash1:
    print("Username or password incorrect.")
    if counter > 1:
        print("Too many tries! Wait 5 seconds.")
        time.sleep(5)
        counter = 0
    counter += 1
    
    password = getpass.getpass("Password:")
    hash1 = PBKDF2(password, bytes.fromhex(tmp_salt), 64, count=1000000, hmac_hash_module=SHA512).hex()

if change_pass == "0":
    print("Login successful.")
else:
    #TREBA PROMJENIT PASSWORD
    new_password = getpass.getpass("New password:")
    repeat_new_password = getpass.getpass("Repeat new password:")
    pass_check = PBKDF2(new_password, bytes.fromhex(tmp_salt), 64, count=1000000, hmac_hash_module=SHA512).hex()
    
    if new_password == repeat_new_password and check_password_complexity(new_password) and tmp_pass != pass_check:
        change_pass = "0"
        new_salt = get_random_bytes(16)
        tmp_pass = PBKDF2(new_password, new_salt, 64, count=1000000, hmac_hash_module=SHA512)
        newData = createString(user, tmp_pass, separator, change_pass, new_salt)
        for each in data:
            if each.split("--")[0] == user:
                data.remove(each)
        data.append(newData)
        e = open("data.txt", "w")
        for each in data:
            e.write(each + "\n")
        print("Login successful.")
    elif(tmp_pass == pass_check):
        print("Cannot use the same password!")
    else:
        print("Password mismatch! Or password too weak.")
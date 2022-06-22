import sys
import json
import os
import re
import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

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
    string = user + separator + hash_password.hex() + separator + salt.hex() + separator + flag + "\n"
    return string

def add(user):
    separator = "--"
    users = []
    for each in f:
        each = each.replace("\n", "")
        users.append(each.split("\n")[0])
        if each.split(separator)[0] == user:
            print("User already exists!")
            return

    password = getpass.getpass('Password: ')
    repeat_password = getpass.getpass('Repeat password: ')

    if password == repeat_password and check_password_complexity(password):
        salt = get_random_bytes(16)
        hash_password = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
        flag = "0"
        tmp = createString(user, hash_password, separator, flag, salt)
    else:
        print("User add failed. Password mismatch. Or password too weak.")
        return
    f.write(tmp)
    print("User add successfuly added.")

def passwd(user):
    data = []
    users = []
    for each in f:
        each = each.replace("\n", "")
        data.append(each)
        users.append(each.split("--")[0])
    if user not in users:
        print("User doesnt exist!")
        return
    else:
        password = getpass.getpass('Password: ')
        repeat_password = getpass.getpass('Repeat password: ')
        if password == repeat_password and check_password_complexity(password):
            salt = get_random_bytes(16)
            hash_password = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
            flag = "0"
            for each in data:
                if each.split("--")[0] == user:
                    index = data.index(each)
                    each = each.replace(each.split("--")[1], hash_password.hex())
                    each = each.replace(each.split("--")[2], salt.hex())
                    data[index] = each
            e = open("data.txt", "w")
            for each in data:
                e.write(each + "\n")
            print("Password change successful.")
        else:
            print("Password change failed. Password mismatch or password too weak.")
            return

def forcepass(user):
    data = []
    for each in f:
        each = each.replace("\n", "")
        data.append(each)
    for each in data:
        if each.split("--")[0] == user:
            tmp = each.split("--")
            tmp[3] = "1"
            stringText = '--'.join(tmp)
            data.remove(each)
            data.append(stringText)

    e = open("data.txt", "w")
    for each in data:
        e.write(each + "\n")
    print("User will be requested to change password on next login.")

def delete(user):
    data = []
    for each in f:
        each = each.replace("\n", "")
        data.append(each)
    for each in data:
                if each.split("--")[0] == user:
                    data.remove(each)
    e = open("data.txt", "w")
    for each in data:
        e.write(each + "\n")
    print("User successfuly removed.")


if os.path.isfile('data.txt'):
    f=open("data.txt", "r+")
else:
    f=open("data.txt", "w+")

globals()[sys.argv[1]](sys.argv[2])
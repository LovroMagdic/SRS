import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt

def encrypt(msg, password):
    salt = get_random_bytes(16)
    secretKey = scrypt(password, salt, key_len=16, N=16384, r=8, p=1)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(pad(msg, 256))
    f = open("pm.txt", "wb")
    separator = bytes(">~~<", "utf-8")
    f.write(ciphertext + separator + aesCipher.nonce + separator + authTag + separator + salt)
    f.close()
    return

def decrypt(ciphertext, nonce, authTag, salt, password):
    secretKey = scrypt(password, salt, key_len=16, N=16384, r=8, p=1)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    try:
        plaintext = unpad(aesCipher.decrypt_and_verify(ciphertext, authTag), 256)
        return plaintext
    except:
        print("Wrong master password or password manager is corrupted!")
        exit()

def init(mp): # python pm.py init "masterPassword"
    password = mp
    mpb = bytes(mp, "utf-8")
    msg = bytes("ovo je poruka", "utf-8")
    encrypt(msg, password)
    print("Password manager initialized")

def put(a): # python pm.py put "masterPassword www.fer.hr zaporka"
    arrayPut = []
    isNew = True
    space = bytes("\n", "utf-8")
    separator = bytes(">~~<", "utf-8")
    userInput = a.split()
    master = userInput[0]
    adresa = userInput[1]
    sifra = userInput[2]

    masterB = bytes(master, "utf-8")
    content = adresa + " " + sifra
    contentB = bytes(content, "utf-8")

    pm = open("pm.txt", "rb")
    data = pm.read()
    dataS = data.split(separator)

    ciphertext = dataS[0]
    nonce = dataS[1]
    authTag = dataS[2]
    salt = dataS[3]
    password = masterB

    decryptedData = decrypt(ciphertext, nonce, authTag, salt, password)
    decryptedDataS = decryptedData.decode("utf-8")
    contet = decryptedDataS.split("\n")

    for each in contet:
        i=0
        eachData = each.split()
        arrayPut.append(eachData[i])
        i += 1
    if adresa in arrayPut:
        decryptedDataS = decryptedDataS.replace("\n" + adresa, "")
        new = bytes(decryptedDataS, "utf-8")
        encrypt(new + space + contentB, masterB)
        isNew = False
    
    if isNew:
        encrypt(decryptedData + space + contentB, masterB)
    print("Stored password for "+ adresa)


    pm.close()

def get(b): # python pm.py get "masterPassword www.fer.hr"
    array =[]
    arrayGet = []
    isNew = True
    separator = bytes(">~~<", "utf-8")
    userInput = b.split()
    master = userInput[0]
    adresa = userInput[1]

    masterB = bytes(master, "utf-8")
    adresaB = bytes(adresa, "utf-8")

    pm = open("pm.txt", "rb")
    data = pm.read()
    dataS = data.split(separator)

    ciphertext = dataS[0]
    nonce = dataS[1]
    authTag = dataS[2]
    salt = dataS[3]
    password = masterB

    decryptedData = decrypt(ciphertext, nonce, authTag, salt, password)
    decryptedDataS = decryptedData.decode("utf-8")
    content = decryptedDataS.split("\n")

    for each in content:
        i = 0
        eachData = each.split()
        array.append(eachData[i])
        arrayGet.append(eachData[i] + " " + eachData[i+1])
        i += 1
    if adresa in array:
        isNew = False
        index = array.index(adresa)
        tmp = arrayGet[index].split()
        print("Password for " + tmp[0] + " is " + tmp[1])
    if isNew:
        print("There is no password for " + adresa)
    array = []
    arrayGet = []
    pm.close()


#encrypt i decrypt su vecinom inspirirani sa linka https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples

if __name__ == '__main__':
    globals()[sys.argv[1]](sys.argv[2])











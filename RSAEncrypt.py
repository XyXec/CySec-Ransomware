import errno
import os
import constants
import MACEncrypt
import KeyGen
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from pathlib import Path



def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    if not os.path.isfile(RSA_Publickey_filepath):
        print("Invalid filepath for RSA public key.")
        return None, None, None, None, None

    #encrypting file
    C, IV, tag, enc_key, HMACKey, ext = MACEncrypt.MyFileEncryptMAC(filepath)
    
    #reading in / loading pem public key
    file = open(RSA_Publickey_filepath, 'rb')
    public_key = serialization.load_pem_public_key(
        file.read(),
        backend = default_backend()
    )
    file.close()

    #concatenating encoding and hmac keys
    key = enc_key + HMACKey
    
    #encrypting key variable
    RSACipher = public_key.encrypt(
        key,
        assym_padding.OAEP(
            mgf = assym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(filepath, RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    
    #read in private key
    file = open(RSA_Privatekey_filepath, 'rb')
    private_key = serialization.load_pem_private_key(
        file.read(),
        password = None,
        backend = default_backend()
    )
    file.close()

    #decryption
    RSA_enc_HMAC_key = private_key.decrypt(
        RSACipher,
        assym_padding.OAEP(
            mgf = assym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    #split RSA key into enc_key and HMACKey
    enc_key = RSA_enc_HMAC_key[:constants.KEY_LENGTH]
    HMACKey = RSA_enc_HMAC_key[constants.KEY_LENGTH:]
    
    #writing out to file
    MACEncrypt.MyFileDecryptMAC(filepath, C, IV, tag, enc_key, HMACKey, ext)
    return

#test bed
#RSACipher, C, IV, tag, ext = MyRSAEncrypt(constants.IMG_PATH, constants.RSA_PUBLIC_KEYPATH)
#print(RSACipher)
#MyRSADecrypt(constants.DECR_IMG_PATH, RSACipher, C, IV, tag, ext, constants.RSA_PRIVATE_KEYPATH)

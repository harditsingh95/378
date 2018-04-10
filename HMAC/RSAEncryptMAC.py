import os 
import myEncryptionMAC
import myDecryptionMAC
import constants
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes, serialization, hmac


def myRSAEncrypt(filepath,RSA_publickey_filepath):
  #Encrypt file
  cipher, IV, tag, key, hmacKey, ext = myEncryptionMAC.MyFileEncrypt(filepath)
  #Load key and create RSACipher
  pubKey = serialization.load_pem_public_key(open(RSA_publickey_filepath, "rb").read(),backend=default_backend())
  #Concatenate the given key and hmackey into RSACipher. Return data for JSON file
  RSACipher = pubKey.encrypt(key + hmacKey,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
  return RSACipher, cipher, IV, tag, ext

def myRSADecrypt(RSACiph, c, iv, tag, ext, privPath):
 #Open key at privpath and decrypt it, then pass to function.
 privKey = open(privPath, "rb").read()
#Load the key and decrypt
 key  = serialization.load_pem_private_key(privKey, password=None, backend=default_backend())
 decryptedKeys = key.decrypt(RSACiph, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
 #Encrypyion key will be first 32 chars, hKey is second set of 32
 encKey = decryptedKeys[0:constants.keyLength]
 hKey = decryptedKeys[constants.keyLength:]
 #Pass decrypted key along with other params to decrypt
 myDecryptionMAC.MyFileDecrypt(c,iv,tag,encKey,hKey, ext)

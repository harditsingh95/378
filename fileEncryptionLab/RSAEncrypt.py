import os 
import myEncryption
import myDecryption
import constants
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
def myRSAEncrypt(filepath,RSA_publickey_filepath):
  #Encrypt file
  cipher, IV, key, ext = myEncryption.MyFileEncrypt(filepath)
  #Load key and create RSACipher
  pubKey = serialization.load_pem_public_key(open(RSA_publickey_filepath, "rb").read(),backend=default_backend())
  RSACipher = pubKey.encrypt(key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
  return RSACipher, cipher, IV, ext

def myRSADecrypt(RSACiph, c, iv,ext, privPath):
 #Open key at path and decrypt it, then pass to function.
 privKey = open(privPath, "rb").read()
 key  = serialization.load_pem_private_key(privKey, password=None, backend=default_backend())
 decryption = key.decrypt(RSACiph, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
 #Pass decrypted key along with other params to decrypt
 myDecryption.MyFileDecrypt(c,iv,decryption, ext)
 return decryption

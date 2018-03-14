import os 
import myEncryption
import myDecryption
import constants
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
def myRSAEncrypt(filepath,RSA_publickey_filepath):
  #Encrypt file
  cipher, IV, key, ext = myEncryption.MyFileEncrypt(filepath)
  #Load public key and Encrypt
  pubKey = serialization.load_pem_public_key(open(RSA_publickey_filepath, "rb").read(),backend=default_backend())
  print (pubKey)
  #RSACipher = pubKey.encrypt(key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
  RSACipher = 0
  return RSACipher, cipher, IV, ext

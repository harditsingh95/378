import os 
import myEncryption
import myDecryption
import constants
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def myRSAEncrypt(filepath,RSA_publickey_filepath):
  #Encrypt file
  cipher, IV, key, ext = myEncryption.MyFileEncrypt(filepath)
  #Load public key and Encrypt
  with open(RSA_publickey_filepath) as key_file:
    pubKey = serialization.load_pem_public_key(key_file.read(),password=None,backend=default_backend())
  RSACipher = pubKey.encrypt(cipher,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
  return RSACipher, cipher, IV, ext

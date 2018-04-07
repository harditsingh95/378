import os
import base64
from base64 import b64encode,b64decode
import constants
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
def MyEncrypt(message, key):
	if len(key) == 32:
		#Generate random variable for IV lrngth of ivLength
		IV = os.urandom(constants.ivLength)
		#Create ciphertext in CBC mode
		encryptor = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend()).encryptor()
		#Pad data so that it meets bit amount needed
		padder = padding.PKCS7(constants.blockSize).padder()
		padData = padder.update(message) + padder.finalize()
		cipherText = encryptor.update(padData) +encryptor.finalize()
		##cipherText = encryptor.update(byteMessage) + encryptor.finalize()
	else:
		cipherText = 0;
		IV = 0
		print("Error:32 byte key is needed to encrypt.")
	return cipherText, IV
def MyFileEncrypt(filepath):
	#Generate a random key for file
	key = os.urandom(constants.keyLength)
	#SPlit filepath in two, name and extension
	fileName, ext = os.path.splitext(filepath)
	#Read jpg file and save it as a string
	with open(filepath, "rb") as jpgFile:
		fileAsAString = base64.b64encode(jpgFile.read())
	#Call MyEncrypt to encode string as ciphertext
	cipher, IV = MyEncrypt(fileAsAString, key)
return cipher, IV, key, ext
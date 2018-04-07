import os
import base64
from base64 import b64encode,b64decode
import constants
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
def MyEncrypt(message, key, hmacKey):
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
		#HMAC Implementation
		tag = hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
		tag.update(cipherText)
		tag.finalize()
	else:
		cipherText = 0;
		IV = 0
		tag = 0
		print("Error:32 byte key is needed to encrypt.")
	return cipherText, IV, tag
def MyFileEncrypt(filepath):
	#Generate a random key for file
	key = os.urandom(constants.keyLength)
	hmacKey = os.urandom(constants.keyLength)
	#Split filepath in two, name and extension
	fileName, ext = os.path.splitext(filepath)
	#Read jpg file and save it as a string
	with open(filepath, "rb") as jpgFile:
		fileAsAString = base64.b64encode(jpgFile.read())
	#Call MyEncrypt to encode string as ciphertext, passing key and hmacKey created in this func
	cipher, IV, tag = MyEncrypt(fileAsAString, key, hmacKey)
	return cipher, IV, tag, key, hmacKey, ext

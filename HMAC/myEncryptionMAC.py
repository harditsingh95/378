import os
import base64
from base64 import b64encode,b64decode
import constants
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa

def MyEncrypt(message, encryptKey, hmacKey):
	if len(encryptKey) == 32:
		#Generate random variable for IV length of ivLength
		IV = os.urandom(constants.ivLength)
		#Create ciphertext in CBC mode, using encryptKey for AES
		encryptor = Cipher(algorithms.AES(encryptKey), modes.CBC(IV), backend=default_backend()).encryptor()
		#Pad message so that it meets bit amount needed, update and finalize. cipherText variable will hold final product
		padder = padding.PKCS7(constants.blockSize).padder()
		padData = padder.update(message) + padder.finalize()
		cipherText = encryptor.update(padData) +encryptor.finalize()
		#HMAC Implementation
		#tG will be assigned HMAC key and update it to cipherText
		tG = hmac.HMAC(hmacKey, hashes.SHA256(), backend=default_backend())
		tG.update(cipherText)
		#tag variable will hold final HMAC info
		tag = tG.finalize()
	else:
		cipherText = 0;
		IV = 0
		tag = 0
		print("Error:32 byte key is needed to encrypt.")
	#Return to myFileEncrypt
	return cipherText, IV, tag
def MyFileEncrypt(filepath):
	#Generate a random encryptionKey and HMAC keys from entropy pool
	encryptKey = os.urandom(constants.keyLength)
	hmacKey = os.urandom(constants.keyLength)
	#Split passed in filepath in two, its name and extension (.txt .jpg or whatever)
	fileName, ext = os.path.splitext(filepath)
	#Open and read the file, then save it as a string
	with open(filepath, "rb") as anyFile:
		fileAsAString = base64.b64encode(anyFile.read())
	#Call MyEncrypt to encode string as ciphertext, passing encryption key and hmacKey created in this func
	cipher, IV, tag = MyEncrypt(fileAsAString, encryptKey, hmacKey)
	#return to RSAEncryptMAC
	return cipher, IV, tag, encryptKey, hmacKey, ext

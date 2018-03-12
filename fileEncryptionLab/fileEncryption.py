import os

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding

keyLength = 32
#key must be 32 bytes in length
ivLength = 16
#Independent variable will be 16 bytes
blockSize = 128
def MyEncrypt(message, key):
	# print (len(key))
	if len(key) == 32:
		#Generate random variable for IV lrngth of ivLength
		print "Plaintext message:", message
		IV = os.urandom(ivLength)
		ciph = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
		encryptor = ciph.encryptor();	
		padder = padding.PKCS7(blockSize).padder()
		padData = padder.update(message) + padder.finalize()
		cipherText = encryptor.update(padData) +encryptor.finalize()
		print("Encrypted message:", cipherText)
	else:
		cipherText = 0;
		IV = 0
		print("Error:32 byte key is needed to encrypt.")
	return cipherText, IV

def MyDecrypt(cipherText,IV, key):
	print "Attempting to decrypt message..."
	plain = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
	decryptor = plain.decryptor()
	plainText = decryptor.update(cipherText) + decryptor.finalize()
	print "Decrypted message: ", plainText
#Generate a random key for cpher text of length keyLength
key = os.urandom(keyLength)
#Encrypt following message
cipherText, iv = MyEncrypt("Hello everyone!This is my unencryped message!", key)
MyDecrypt(cipherText, iv, key)


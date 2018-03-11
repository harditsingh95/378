import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding

keyLength = 32
#key must be 32 bytes in length
ivLength = 16
#Independent variable will be 16 bytes

def MyEncrypt(message, key)
	if len(key) < 32
		Ciph = 0
		IV = 0
		print("Error: key length must be at least 32 byte to be encrypted")
	else:
		#Generate random variable for IV lrngth of ivLength
		IV = os.urandom(ivLength)
		encryptor = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend()).encryptor()
		
		Ciph = encryptor.update(message) +encryptor.finalize()
		return (Ciph, IV)
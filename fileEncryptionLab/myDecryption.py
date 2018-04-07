import os
import constants
import myEncryption
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
def MyDecrypt(cipherText,IV, key):
	print ("Attempting to decrypt message...")
	#Generate plain text from given cipherText
	plain = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
	decryptor = plain.decryptor()
	plainText = decryptor.update(cipherText) + decryptor.finalize()
	unpadder = padding.PKCS7(constants.blockSize).unpadder()
	plainText = unpadder.update(plainText) + unpadder.finalize()
	return plainText

def MyFileDecrypt(cipher, iv, key, ext):
	#Get plaintext from cipherText in MyDecrypt function
	plainText = MyDecrypt(cipher, iv,key)
	#Ask user for filename for new file
	fileLoc = input("What would you like to save the file as? ")
	newFile = fileLoc + ext
	#Create new file, write to it
	nF = open(newFile, "wb")
	nF.write(base64.b64decode(plainText))
	nF.close()
print ("File decrypted!")
import os
import constants
import myEncryption
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
def MyDecrypt(cipherText,IV, tag, key, hKey):
	print ("Attempting to decrypt message...")
	#Load hKey and verify it matches with the tag
	hm = hmac.HMAC(kKey, hashes.SHA256(), backend=default_backend())
	hm.update(cipherText)
	hm.verify(tag)
	#Generate plain text from given cipherText
	plain = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
	decryptor = plain.decryptor()
	plainText = decryptor.update(cipherText) + decryptor.finalize()
	unpadder = padding.PKCS7(constants.blockSize).unpadder()
	plainText = unpadder.update(plainText) + unpadder.finalize()
	return plainText

def MyFileDecrypt(cipher, iv, tag, key, hKey, ext):
	#Get plaintext from cipherText in MyDecrypt function
	plainText = MyDecrypt(cipher, iv,tag, key ,hKey)
	#Ask user for filename for new file
	fileLoc = input("What would you like to save the file as? ")
	newFile = fileLoc + ext
	#Create new file, write to it
	nF = open(newFile, "wb")
	nF.write(base64.b64decode(plainText))
	nF.close()
	print ("File decrypted!")

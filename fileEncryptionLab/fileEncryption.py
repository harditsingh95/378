import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms, modes)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
keyLength = 32
#key must be 32 bytes in length
ivLength = 16
#Independent variable will be 16 bytes
blockSize = 128
my_private_key = rsa.generate_private_key(public_exponent = 65537, key_size=1024, backend=default_backend())
my_public_key = my_private_key.public_key()
fPrivKey = open("private.pem", "wb")
fPrivKey.write(my_private_key.exportKey('PEM'))
fPrivKey.close()
def MyEncrypt(message, key):
	if len(key) == 32:
		#Generate random variable for IV lrngth of ivLength
		IV = os.urandom(ivLength)
		#Create ciphertext in CBC mode
		ciph = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
		encryptor = ciph.encryptor();
		#Pad data so that it meets bit amount needed
		padder = padding.PKCS7(blockSize).padder()
		padData = padder.update(message) + padder.finalize()
		cipherText = encryptor.update(padData) +encryptor.finalize()
	else:
		cipherText = 0;
		IV = 0
		print("Error:32 byte key is needed to encrypt.")
	return cipherText, IV

def MyDecrypt(cipherText,IV, key):
	print ("Attempting to decrypt message...")
	#Generate plain text from given cipherText
	plain = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
	decryptor = plain.decryptor()
	plainText = decryptor.update(cipherText) + decryptor.finalize()
	unpadder = padding.PKCS7(blockSize).unpadder()
	plainText = unpadder.update(plainText) + unpadder.finalize()
	return plainText
def MyFileEncrypt(filepath):
	#Generate a random key for file
	key = os.urandom(keyLength)
	#SPlit filepath in two, name and extension
	fileName, ext = os.path.splitext(filepath)
	#Read jpg file and save it as a string
	with open(filepath, "rb") as jpgFile:
		fileAsAString = base64.b64encode(jpgFile.read())
	#Call MyEncrypt to encode string as ciphertext
	cipher, IV = MyEncrypt(fileAsAString, key)
	#Prompt user for what they would like to save the name as and add custom extension
	saveAs = raw_input("Save file as: ")
	fileEncrypted = saveAs + ".encrypted"
	#Create new file and write cipher text to it
	fEncrypt = open(fileEncrypted,"wb")
	fEncrypt.write(cipher)
	fEncrypt.close()
	return cipher, IV, key, ext
def MyFileDecrypt(cipher, iv, key, ext):
	#Get plaintext from cipherText in MyDecrypt function
	plainText = MyDecrypt(cipher, iv,key)
	#Ask user for filename for new file
	fileLoc = raw_input("What would you like to save the file as? ")
	newFile = fileLoc + ext
	#Create new file, write to it
	nF = open(newFile, "wb")
	nF.write(base64.b64decode(plainText))
	nF.close()
	print ("File decrypted!")
def main():
	print ("###JPG file encrypter###")
	message = raw_input("Please enter a message to encrypt. A random key will be generated for you.")
	key = os.urandom(keyLength)
	c, iv = MyEncrypt(message, key)
	print "Ciphertext of your message: ", c
	print "IV of your message: ",iv
	plain = MyDecrypt(c, iv, key)
	print "Now decoding your message..."
	print plain
	#Prompt user until valid file is found or chooses to exit
	while(True):
		encryptedFile = raw_input("Enter the location of the file you want encrypted (E to exit): ")
		if encryptedFile =="E":
			break;
		if os.path.isfile(encryptedFile):
			cipherText, iv, key, ext = MyFileEncrypt(encryptedFile)
			MyFileDecrypt(cipherText, iv, key, ext)
		else:
			print "File not found!"
if __name__=="__main__":
	main()

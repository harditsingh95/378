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
message = "Hello! This is an unencrypted message!"
encryptedFile = 'Encrypted'

def MyEncrypt(message, key):
	# print (len(key))
	if len(key) == 32:
		#Generate random variable for IV lrngth of ivLength
		IV = os.urandom(ivLength)
		ciph = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
		encryptor = ciph.encryptor();	
		padder = padding.PKCS7(blockSize).padder()
		padData = padder.update(message) + padder.finalize()
		cipherText = encryptor.update(padData) +encryptor.finalize()
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
	unpadder = padding.PKCS7(blockSize).unpadder()
	plainText = unpadder.update(plainText) + unpadder.finalize()
	return plainText
#Generate a random key for cpher text of length keyLength
key = os.urandom(keyLength)
#Encrypt following message
##print "Unencrypted message: ", message
##cipherText, iv = MyEncrypt(message, key)
##print "Encrypted message: ", cipherText
##print MyDecrypt(cipherText, iv, key)


def MyFileEncrypt(filepath):
	key = os.urandom(keyLength)
	#SPlit filepath in two
	fileName, ext = os.path.splitext(filepath)
	with open(filepath, "rb") as jpgFile:
		fileAsAString = base64.b64encode(jpgFile.read())
	cipher, IV = MyEncrypt(fileAsAString, key)
	saveAs = input("Save file as:")
	fileEncrypted = saveAs + ext
	fEncrypt = open(fileEncrypted,"wb")
	fEncrypt.write(cipher)
	fEncrypt.close()
	return cipher, IV, key, ext
def MyFileDecrypt(cipher, iv, key, ext):
	plainText = MyDecrypt(cipher, iv,key)
	#unpadding?
	fileLoc = input("What would you like to save the file as?")
	newFile = fileLoc + ext
	nF = open(newFile, "wb")
	nF.write(plainText)
	nF.close()
	print "File decrypted"
	
# TEST - cipherText, iv, key, ext = MyFileEncrypt('Alliance.png')
def main():
	encryptedFile = input("Enter the location of the file you want encryted")
	cipherText, iv, key, ext = MyFileEncrypt(encryptedFile)
	MyFileDecrypt(cipherText, iv, key, ext)
if __name__=="__main__":
	main()

#Various imports 
import myEncryption
import myDecryption
import os
import constants
import RSAEncrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Beginning of main
#Need to separate this and make it prompt user 
def main():
	print ("###JPG file encrypter###")
	message = raw_input("Please enter a message to encrypt. A random key will be generated for you.")
	key = os.urandom(constants.keyLength)
	c, iv = myEncryption.MyEncrypt(message, key)
	print "Ciphertext of your message: ", c
	print "IV of your message: ",iv
	plain = myDecryption.MyDecrypt(c, iv, key)
	print "Now decoding your message..."
	print plain
	#Prompt user until valid file is found or chooses to exit
	encryptedFile = promptForFile()
	if encryptedFile !="E":
		cipherText, iv, key, ext = myEncryption.MyFileEncrypt(encryptedFile)
		myDecryption.MyFileDecrypt(cipherText, iv, key, ext)
	print ("Time to generate an RSA key:")
	#Prompt user for path, then generate private key
	RSA_key_path = input("Please enter the path where you would like to save the keys: ")
	rsaPrivKey = rsa.generate_private_key(public_exponent=65537, key_size = 2048, backend = default_backend())
	#Generate public key from privatekey
	rsaPubKey = rsaPrivKey.public_key()
	#Serialize keys for file
	privPem = rsaPrivKey.private_bytes(encoding=serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
	pubPem = rsaPubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	#Write keys to file
	os.makedirs(RSA_key_path)
	createFile = open(RSA_key_path+".pem", "wb")
	createFile.write(privPem)
	createFile.close()
	createFile = open(RSA_key_path+".pub", "wb")
	createFile.write(pubPem)
	createFile.close()
	encryptedFile = promptForFile()
	RSACipher, cipher, IV, ext = RSAEncrypt.myRSAEncrypt(encryptedFile, RSA_key_path)
#End of main()
def promptForFile():
	while(True):
		userFile = raw_input("Enter location of file: ")
		if userFile == "E":
			return userFile
		if os.path.isfile(userFile):
			return userFile
		else:
			print ("File not found!")
if __name__=="__main__":
  main()

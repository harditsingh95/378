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
def main():
	#Prompt user until valid file is found or chooses to exit
	encryptedFile = promptForFile()
	if encryptedFile !="E":
		cipherText, iv, key, ext = myEncryption.MyFileEncrypt(encryptedFile)
		myDecryption.MyFileDecrypt(cipherText, iv, key, ext)
	print ("RSA key generation")
	print ("A public key and private key will be generated with file you provide.")
	#Prompt user for path, then generate private key
	RSA_key_path = input("Please enter the path where you would like to save the keys and name: ")
	rsaPrivKey = rsa.generate_private_key(public_exponent=65537, key_size = 2048, backend = default_backend())
	#Generate public key from privatekey
	rsaPubKey = rsaPrivKey.public_key()
	#Serialize keys for file
	privPem = rsaPrivKey.private_bytes(encoding=serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
	pubPem = rsaPubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	#Write keys to file
	kPath, kName =os.path.split(RSA_key_path)
	print (kPath)
	print (kName)
	#Check if path is a directory, create it if it does not exist
	if kPath != "":
		os.makedirs(kPath)
	#if there is no tail, add "default" to key path for key gen 
	if kName == "":
		print ("No name entered. default.pem, default.pub will be created in chosen directory")
		RSA_key_path = RSA_key_path + "default"
	#Write keys to files
	createFile = open(RSA_key_path+".pem", "wb")
	createFile.write(privPem)
	createFile.close()
	createFile = open(RSA_key_path+".pub", "wb")
	createFile.write(pubPem)
	createFile.close()
	print ("Enter the location of the file you would like to RSA encrypt")
	encryptedFile = promptForFile()
	print ("Enter location of the public key (.pub extension): ")
	rsaPath = promptForFile()
	RSACipher, cipher, IV, ext = RSAEncrypt.myRSAEncrypt(encryptedFile,rsaPath)
	print ("Let's decrypt that file:")
	print("Enterlocation of private key(.pem extension):")
	privPath = promptForFile()
	RSAEncrypt.myRSADecrypt(RSACipher, cipher, IV, ext, privPath)
#End of main()
def promptForFile():
	while(True):
		userFile = input("Enter location of file: ")
		if userFile == "E":
			return userFile
		if os.path.isfile(userFile):
			return userFile
		else:
			print ("File not found!")
if __name__=="__main__":
  main()

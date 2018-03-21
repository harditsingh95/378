#Various imports 
import myEncryption
import myDecryption
import os
import constants
import RSAEncrypt
import json
from base64 import base64encode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Beginning of main 
def main():
	print("***HJ Corp Encryptor***")
	print("Enter one of the following commands:")
	print("generate RSAkey")
	print("encrypt (name-of-file.extension)")
	print("decrypt (.cryp file)")
	userOp= input("Choose a command:")
	#split the input into 2 parts
	opCommand, fileSplit = userOp.split(" ")
	if opCommand == 'generate':
		RSA_key_path = input("Please enter the path where you would like to save the keys and name: ")
		rsaPrivKey = rsa.generate_private_key(public_exponent=65537, key_size = 2048, backend = default_backend())
	#Generate public key from privatekey
		rsaPubKey = rsaPrivKey.public_key()
	#Serialize keys for file
		privPem = rsaPrivKey.private_bytes(encoding=serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
		pubPem = rsaPubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	#split path from file name
		kPath, kName =os.path.split(RSA_key_path)
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
		print(kName,".pem and ", kName,".pub have been created at ",kPath)
	#cipherText, iv, key, ext = myEncryption.MyFileEncrypt(encryptedFile)
	#myDecryption.MyFileDecrypt(cipherText, iv, key, ext)
	#Prompt user for path, then generate private key

	if opCommand =='encrypt':
		print ("Enter the location of the file you would like to RSA encrypt")
		encryptedFile = promptForFile()
		print ("Enter location of the public key (.pub extension): ")
		rsaPath = promptForFile()
		RSACipher, cipher, IV, ext = RSAEncrypt.myRSAEncrypt(encryptedFile,rsaPath)
	#Prompt user for what they would like to save the name as and add custom extension
		saveAs = input("Save encrypted file as (will be assigned .cryp extension: ")
		fileEncrypted = saveAs + ".cryp"
	#Create new file and write cipher text to it
		fEncrypt = open(fileEncrypted,"w")
		fileInfo = {}
		fileInfo["key"] = b64encode(RSACipher).decode('utf-8')
		fileInfo["cipher"] = b64encode(cipher).decode('utf-8')
		fileInfo["iv"] = b64encode(IV).decode('utf-8')
		fileInfo["ext"] = ext
		json.dump(fileInfo, fEncrypt)
		fEncrypt.close()
	if opCommand == 'decrypt':
		print("Enter location of private key(.pem extension):")
		privPath = promptForFile()
		RSAEncrypt.myRSADecrypt(RSACipher, cipher, IV, ext, privPath)
#End of main

def promptForFile():
	#Prompt to check if file path is valid. E to exit
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

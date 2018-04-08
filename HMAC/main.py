#Various imports 
import myEncryptionMAC
import myDecryptionMAC
import os
import constants
import RSAEncryptMAC
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Beginning of main 
def main():
	while(True):
		print("***HJ Corp Encryptor***")
		print("Select the number of one of the following commands:")
		print("1) Generate RSA tokens")
		print("2) Encrypt a file using RSA")
		print("3) Decrypt a file ")
		opCommand = input("Choose a command:")
		if opCommand == "1":
			RSA_key_path = "keys/rsa"
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
				os.makedirs(kPath, exist_ok=True)
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
			print(kName,".pem and ", kName,".pub have been created in the",kPath, "/ folder")
	#User enters encrypt option
		elif opCommand =='2':
			print ("Enter the location of the file you would like to RSA encrypt")
			encryptedFile = promptForFile()
			print ("Enter location of the public key (.pub extension): ")
			rsaPath = promptForFile()
			RSACipher, cipher, IV, tag, ext = RSAEncryptMAC.myRSAEncrypt(encryptedFile,rsaPath)
			jsonPack(RSACipher, cipher, IV, tag, ext)
			print("Encryption complete.")
		elif opCommand == '3':
			print("Enter the path of the the file you want to decrypt.")
			dFile = promptForFile()	
			RSACipher, cipher, IV, tag, ext= jsonUnpack(dFile)
			print("Enter location of private key(.pem extension):")
			privPath = promptForFile()
			RSAEncryptMAC.myRSADecrypt(RSACipher, cipher, IV, tag, ext, privPath)
		elif opCommand == '4':
			print("Exiting...")
			break;
		else:
			print("Error command")	
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
def jsonPack(Enckey, cipher, IV, tag, ext):
#Prompt user for what they would like to save the name as and add custom extension
	saveAs = input("Save encrypted file as (will be assigned .cryp extension: ")
	fileEncrypted = saveAs + ".cryp"
	#Create new file and write cipher text to it
	fEncrypt = open(fileEncrypted,"w")
	fileInfo = {}
	fileInfo["key"] = b64encode(Enckey).decode('utf-8')
	fileInfo["cipher"] = b64encode(cipher).decode('utf-8')
	fileInfo["iv"] = b64encode(IV).decode('utf-8')
	fileInfo["tag"] = b64encode(tag).decode('utf-8')
	fileInfo["ext"] = ext
	json.dump(fileInfo, fEncrypt)
	fEncrypt.close()
def jsonUnpack(filepath):
	jsonFile = open(filepath, 'r')
	jLoad = json.load(jsonFile)
	jsonFile.close()
	jKey = b64decode(jLoad["key"])
	jCipher = b64decode(jLoad["cipher"])
	jIV = b64decode(jLoad["iv"])
	jExt = jLoad["ext"]
	jTag = b64decode(jLoad["tag"])
	return jKey, jCipher, jIV, jTag, jExt
if __name__=="__main__":
	main()

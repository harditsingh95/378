
my_private_key = rsa.generate_private_key(public_exponent = 65537, key_size=1024, backend=default_backend())
my_public_key = my_private_key.public_key()
fPrivKey = open("private.pem", "wb")
fPrivKey.write(my_private_key.exportKey('PEM'))
fPrivKey.close()
import myEncryption
import myDecryption
import os
import constants
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
	while(True):
		encryptedFile = raw_input("Enter the location of the file you want encrypted (E to exit): ")
		if encryptedFile =="E":
			break;
		if os.path.isfile(encryptedFile):
			cipherText, iv, key, ext = myEncryption.MyFileEncrypt(encryptedFile)
			myDecryption.MyFileDecrypt(cipherText, iv, key, ext)
		else:
			print "File not found!"
			
if __name__=="__main__":
  main()
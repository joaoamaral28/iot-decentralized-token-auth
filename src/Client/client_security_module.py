from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os

from cryptography.exceptions import InvalidKey, InvalidSignature

# generate a new RSA public key pair and stores it am pem files

def generateRSAKeyPair(password):
	priv_key = rsa.generate_private_key(public_exponent=655537,key_size=2048,backend=default_backend())
	pub_key = priv_key.public_key()

	priv_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(password))
	pub_pem = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


	fname_pub = "public_key_client.pem"
	fname_priv = "private_key_client.pem"

	try:
		with open(fname_pub,"w") as pub_file:
			pub_file.write(pub_pem.decode())
		with open(fname_priv,"w") as priv_file:
			priv_file.write(priv_pem.decode())
	except Exception as exc:
		print("Error occurred while writing key on file")
		print(exc)
		return -1

	return 1

# load a key saved on file as PEM format 
# if a public key is to be read then the reading is standard file read
# if its a private key then the password used to save it on file is required
def loadKeyPEM(uid,type,password=None,path=""):
	if(type=='public'):
		fname = 'public_key_'+str(uid)+'.pem'
		try:
			with open(path+fname, "rb") as key_file:
				key = key_file.read()
			key_file.close()
		except Exception:
			print("Error occurred loading key from file")
			return -1

	elif(type=='private'):
		if(not password):
			print("Error: Password is required to store private key")
			return -1
		fname = 'private_key_'+str(uid)+'.pem'
		try:
			with open(path+fname, "rb") as key_file:
				key = serialization.load_pem_private_key(
					key_file.read(),
					password=password,
					backend=default_backend())
			key_file.close()	
		except Exception % exc:
			print(exc)
			return -1
	else:
		print("Error: Invalid key type. Can only be \"public\" or \"private\" type")
		return -1
	return key

# serialize key as PEM format from object
def serializeKey(key):
	return key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

# load key object from given key in PEM format
def loadKey(key):
	return serialization.load_pem_public_key(key,backend=default_backend())

# password derivation with salting using PBKDF2
def PBKDF2(password, salt):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
	key = kdf.derive(password)
	return key

def verifyPKBDF2(key, password, salt):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
	try:
		if(not kdf.verify(password,key)):
			return 1
	except InvalidKey:
		return 0

# generate digest of data input using SHA256
def digestSHA256(data, salt=None):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(data)
	if(salt):
		digest.update(salt)
	hash =  digest.finalize()
	return hash

# generates a iterative digest with the provided list contents
def digestMultipleSHA256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for d in data:
        digest.update(d)
    return digest.finalize()

def digestMD5(data, arg_list=None):
	digest = hashes.Hash(hashes.MD5(), backend=default_backend())
	digest.update(data)
	if(arg_list):
		for arg in arg_list:
			digest.update(arg)
	return digest.finalize()

# AES encryption of data with key "key" and cipher mode CTR
def encryptAES(data, key):
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
	encryptor = cipher.encryptor()
	encData = encryptor.update(data) + encryptor.finalize()
	return encData, iv

# AES decryption of ciphertext with key "key", initialization vector "iv" and cipher mode CTR
def decryptAES(ciphertext, key, iv):
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def encryptAES_CBC(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    enc_data = encryptor.update(data) + encryptor.finalize()
    return enc_data, iv

def decryptAES_CBC(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# encrypt message using RSA algorithm
def encryptRSA(pub_key, message):
	ciphertext = pub_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
	return ciphertext

# decrypt ciphertext using RSA algorithm 
def decryptRSA(priv_key,ciphertext):
	message = priv_key.decrypt(ciphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
	return message

# create signature from data using given private key 
def signRSA(priv_key, message):
	signature = priv_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	return signature

# validate a given signature of the message data
def validateRSA(pub_key, signature, message):
	try:
		pub_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	except InvalidSignature:
		return 0
	return 1

# calculate a HMAC value from the given data and simmetric key
def generateHMAC(key,data):
	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	h.update(data)
	return h.finalize()

if __name__ == "__main__":
	# 1 # KEY PAIR GENERATION ###
	#password = b"123456789!\"#$%&/()="
	#generateRSAKeyPair(password)
	###########################

	# 2 # KEY PAIR LOADING ###
	#password = b"123456789!\"#$%&/()="
	#pem_pub_key = loadKeyPEM("dhm","public",password=None,path="")
	#priv_key = loadKeyPEM("dhm","private",password,path="")
	#pub_key = loadKey(pem_pub_key)
	#print(pub_key)
	#print(priv_key)
	##########################

	# 3 # SIGN / VALIDATION ###
	#data = b"aaaa"
	#signature = signEC(priv_key, data)
	#print(validateEC(pub_key,signature,b"aa"))
	###########################

	# 4 # PASSWORD STORE WITH SALT IN DHM DB #####
	#import pymongo
	#import os
	#db_client_name = "IOT_A3C_GW_DB"
	#crypto_collection_name = "crypto_info"
	#db_client = pymongo.MongoClient("mongodb://localhost:27017/")	
	#db = db_client[db_client_name]
	#col = db[crypto_collection_name]
	#col.drop()
	#password = b"123456789!\"#$%&/()="
	#salt = os.urandom(16)
	#key = PBKDF2(password, salt)
	#d = {"key":key , "salt":salt }
	#x = col.insert_one(d)
	#for d in col.find({}):
	#	print(d['key'])
	#	print(d['salt'])	
	##############################
	print('A')
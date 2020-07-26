from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os

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
		except Exception as exc:
			print("## Error occurred loading public key from file")
			print("### {}".format(exc))
			return 0

	elif(type=='private'):
		if(not password):
			print("## Error: Password is required to store private key")
			return 0
		fname = 'private_key_'+str(uid)+'.pem'
		try:
			with open(path+fname, "rb") as key_file:
				key = serialization.load_pem_private_key(
					key_file.read(),
					password=password,
					backend=default_backend())
			key_file.close()	
		except Exception as exc:
			print("## Error ocurred while reading private key from file")
			print("### {}".format(exc))
			return 0
	else:
		print("## Error: Invalid key type. Can only be \"public\" or \"private\" type")
		return 0
	return key

# store a key in PEM format on a file on disk
# if its a public key to be stored standard file write is used
# if its a private key then private_bytes method is used and a password is required 
def storeKeyPEM(uid,key,type,password=None,path=""):
    if(type=='public'):
        fname = 'public_key_'+str(uid)+'.pem'
        pem = key.decode()
    elif(type=='private'):
        if(not password):
            print("Error: Password is required to store private key")
            return -1
        fname = 'private_key_'+str(uid)+'.pem'
        pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password)).decode()
    else:
        print("Error: Invalid key type. Can only be \"public\" or \"private\" type")
        return -1

    try:
        with open(path+fname,"w") as file:
            file.write(pem)
    except Exception as exc:
        print("Error occurred while writing key on file")
        print(exc)
        return -1
    return 1

# generates a iterative digest with the provided list contents
def digestMultipleSHA256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for d in data:
        digest.update(d)
    return digest.finalize()

# generate digest of data input using SHA256
def digestSHA256(data, salt=None):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(data)
	if(salt):
		digest.update(salt)
	hash =  digest.finalize()
	return hash

# load key object from given key in PEM format
def loadKey(key):
	return serialization.load_pem_public_key(key,backend=default_backend())
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

# decrypt ciphertext using RSA algorithm 
def decryptRSA(priv_key,ciphertext):
	message = priv_key.decrypt(ciphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
	return message

def digestMD5(data, arg_list=None):
	digest = hashes.Hash(hashes.MD5(), backend=default_backend())
	digest.update(data)
	if(arg_list):
		for arg in arg_list:
			digest.update(arg)
	return digest.finalize()

# calculate a HMAC value from the given data and simmetric key
def generateHMAC(key,data):
	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	h.update(data)
	return h.finalize()

# validates de received HMAC by generating a new one from 
# the given data and comparing them. If they're equal
# then the received HMAC was produced with the same simmetric key and thus valid
def validateHMAC(key,data,hmac):
	new_hmac = generateHMAC(key,data)
	return True if new_hmac==hmac else False

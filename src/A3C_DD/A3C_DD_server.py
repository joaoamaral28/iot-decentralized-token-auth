import pymongo
import os
import base64
import datetime
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler
import threading
import getpass
import json
import operator
import logging
from a3c_dd_security_module import * 

# logger setup
logging.basicConfig(
level=logging.INFO,
format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
handlers=[
    logging.FileHandler("{0}/{1}.log".format(os.getcwd()+"/logs/", "logger")),
    logging.StreamHandler()
])

logger = logging.getLogger()


HOST = "localhost"
PORT = 2222

db_client_name = "IOT_A3C_DD_DB"

col_dd = "dd_info"

db_client = None

dd_list = []

# dictionary containing the connection session properties with the clients 
# A session includes
# 	> session key
# 	> ...
connections = {}

server_pub_key_pem = None
server_pub_key = None
server_priv_key = None

a3c_id = None

# thread responsible for revoking the client session
# every X seconds the thread will check for clients 
class ConnectionManager(threading.Thread):
	def run(self):
		# < TODO >
		print("oi")

# Class to be used if the registration process is initiated
# by the AAA server itself. The server polls for online 
# gateways and sends its information and location to 
# the gateway. The registration is performed by also 
# sending its public key along with its signature.
# < TODO >
class RegistrationManager(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		return

class MainHandler(RequestHandler):
	def get(self):
		self.write("IoT AAA Smarthome Server")

class ticketFetchHandler(RequestHandler):
	def post(self):
		#print("# Ticket request received!")

		# get request arguments & decode
		dd_id = self.get_body_argument('id')
		client_pub_key = base64.b64decode(self.get_body_argument('public_key'))
		enc_nonce1 = base64.b64decode(self.get_body_argument('nonce'))

		client_id = digestMD5(client_pub_key).hex()
		logger.info("Ticket request received from client uuid: " + client_id)

		# check if dhm can access the gateway 
		# this access control is done by checking if the dhm id is is present in the database
		# < TODO > 
		logger.info("Entity is eligible to access target DD: " + dd_id)

		# fetch the DD Public Key from its dd_id
		dd_pub_key_pem = [g for g in dd_list if g['uuid'] == dd_id][0]['pub_key']

		dd_pub_key = loadKey(dd_pub_key_pem.encode())

		# decrypt nonce 1
		nonce1 = decryptRSA(server_priv_key, enc_nonce1)
		# generate nonce 2
		nonce2 = os.urandom(16)
		# calculate session_key = r1 xor r2 
		session_key = bytes(map(operator.xor, nonce1, nonce2))

		# create ticket for session establishment between gateway and DH
		# each ticket is formed by three parts: secret, public, and signature
		## the secret part contains the session key encrypted with the ticket target public key
		secret = encryptRSAPKCS1v15(dd_pub_key,session_key)
		## the public part contains an identifier of the ticket target, a pseudonim of the ticket owner and a set of 
		## rights over the target and the ticket validity date
		ticket_expiration_date = datetime.datetime.now(datetime.timezone.utc).timestamp() + (24*60*60)# expires in 1 day
		#public = {'dd_id' : dd_id, 'owner_id' : client_id, 'access_rights' : 'RxTx', 'expiration_date': ticket_expiration_date}
		public = {'dd_id' : dd_id, 'access_rights' : '[readValue:1, calibrateSensor:0,setUnits:0]', 'expiration_date': ticket_expiration_date}
		# signature of the secret and public parts
		m = secret + str(public).encode()
		print(m)
		signature = signRsaPKCS1v15(server_priv_key, m)

		ticket = {
			'secret': secret, # 128 bit session key
			'public' : base64.b64encode(str(public).encode()),#public,
			'signature': signature,
		}

		logger.info("Ticket generated successfully")

		response = {
			'nonce' : base64.b64encode(encryptRSA(loadKey(client_pub_key), nonce2)),
			'ticket': ticket, #base64.b64encode(bytes(ticket)),
			'public_key': base64.b64encode(server_pub_key_pem)  
		}

		self.write(str(response))

		return

def make_app():
	urls = [
		("/", MainHandler),
		("/ticketFetch/", ticketFetchHandler)
	]
	return Application(urls, debug=True)

def main():

	# server password input
	# it will be used to load the server private key
	#server_password = bytes(getpass.getpass(),'utf-8')
	server_password = b"123456789!\"#$%&/()="

	#print("# IOT A3C DD server starting...")
	logger.info("A3C DD server starting")

	# init database
	logger.info("Loading database")
	global db_client
	db_client = pymongo.MongoClient("mongodb://localhost:27017/")
	db = db_client[db_client_name]
	crypt_col = db["crypto_info"]
	
	logger.info("Fetching hashed password from database")
	for d in crypt_col.find({}):
		db_hash = d['key']
		db_salt = d['salt']	

	if not db_hash:
		logger.critical("Password not found in local database")
		return 
	
	if not db_salt: 
		logger.critical("Password salt value not found in local database ")
		return

	# check if password matches the salted hash stored in database 
	key = PBKDF2(server_password, db_salt)
	
	if(not verifyPKBDF2(key, server_password, db_salt)):
		#print("ERROR: Invalid password!")
		logger.critical("Provided bootstrap password does not match stored password")
		return
	else:
		#print("## Correct password")
		logger.info("Correct bootstrap password")

	# load server key_pair from file
	global server_pub_key_pem
	server_pub_key_pem  = loadKeyPEM("a3c_dd","public")
	if(server_pub_key_pem == -1):
		logger.critical("Failed to load public key")
		return
	logger.info("Public key loaded successfully")
	global server_priv_key
	server_priv_key = loadKeyPEM("a3c_dd","private",password=server_password)
	if(server_priv_key == -1):
		logger.critical("Failed to load private key")
		return
	logger.info("Private key loaded successfully")

	global server_pub_key
	server_pub_key = loadKey(server_pub_key_pem)
	# A3C id is equal to the digest of its public key
	global a3c_id
	a3c_id = digestMD5(server_pub_key_pem).hex()
	
	logger.info("A3C DD Server UUID: " + a3c_id)
	#print("Server ID: " + a3c_id)

	## LOGIN procedure complete ## 

	## Fetch information about the DDs this A3C manages 
	dd_col = db[col_dd]

	for g in dd_col.find({}):
		global dd_list
		dd_list.append({
			'uuid' : g['uuid'],
			'name' : g['name'],
			'manufacturer' : g['manufacturer'],
			'pub_key' : g['public_key'],
			'api' : g['api']
			})

	logger.info("Successfully loaded GWs info from local database")

	#print(dd_list)

	## Init REST/web server ## 
	# init tornado web server
	app = make_app()
	app.listen(PORT) 
	logging.info("Starting web server")       
	IOLoop.current().start()
	
	return

if __name__ == "__main__":
	main()

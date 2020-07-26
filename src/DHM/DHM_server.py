import pymongo
import os
import base64
import datetime
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler
import threading
import getpass
import json
import logging
import ast
import time
from urllib import request, parse 
import requests
import operator
from queue import Queue
from dhm_security_module import * 

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
PORT = 7777

db_client_name = "IOT_DHM_DB"

col_a3c_gw = "a3c_gw_info"
col_gw = "gw_info"
col_dh = "dh_info"

db_client = None

GW_ADDR = "http://192.168.1.79" # Hardcoded gateway address (assuming discovery already occurred inside the local area network)
GW_PORT = "1111" # hardcoded gateway port

# dictionary containing the connection session properties with the clients 
# A session includes
# 	> session key
# 	> ...
connections = {}

# list of devices managed by this dhm server
dh_list = []
# list of gateways to communicate
gw_list = []

# global variables
server_id = None
server_pub_key_pem = None
server_pub_key = None
server_priv_key = None

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
'''
class RegistrationManager(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		return
'''

class MainHandler(RequestHandler):
	def get(self):
		self.write("IoT DHM Server")

# Class to be used if the registration process is initiated by 
# the gateways themselves. They actively wait and search for the 
# AAA server to be operational. When it is they then annouce their
# idenity to the server which must be verified and valid
class RegistrationHandler(RequestHandler):
	def post(self):
		return

class AuthenticationHandler(RequestHandler):
	def post(self):
		return


class DHConfirmHandler(RequestHandler):
	def post(self):
		dh_uuid = self.get_body_argument('dh_uuid')
		status = self.get_body_argument('status')

		print(status)

		if(status == "OK"):
			logger.info("DH " + dh_uuid  +" successfully configured")

	def get(self):
		print("GET")
		
def make_app():
	urls = [
		("/", MainHandler),
		("/authenticationRequest/", AuthenticationHandler),
		("/registrationRequest/", RegistrationHandler),
		("/dhSessionConfirm/", DHConfirmHandler)
	]
	return Application(urls, debug=True)


def authTicketGen(device, derived_key, gw_id):

	key = os.urandom(16) # 128 bit key for GW <-> DH session

	#secret = encryptRSA(loadKey(device['pub_key'].encode()), key)
	secret = encryptRSAPKCS1v15(loadKey(device['pub_key'].encode()), key)

	#print("Session key (K) for GW <-> DH session establishment")
	#for b in key:
	#	print(int(b))

	public = {'dh_id' : device['uuid'], 'dh_addr' : device['ble_addr'], 'owner_id' : gw_id, 'access_rights' : 'Rx', 'ticket_lifetime': 3600}

	m = secret + str(public).encode()

	signature = signRsaPKCS1v15(server_priv_key, m)

	ticket = {
		'secret': secret, #base64.b64encode(secret),
		'public' : base64.b64encode(str(public).encode()),
		'signature': signature #base64.b64encode(signature),
	}

	return ticket, key

# thread responsible for managing the connections and sessions between the DHM and each GW 
class DHM_GW_Session(threading.Thread):
	def __init__(self, queue, gw_addr, gw_id, a3c_pub_key, session_key, ticket, sleep_delta):
		threading.Thread.__init__(self)
		self.queue = queue
		self.gw_addr = gw_addr # url address of the GW
		self.gw_id = gw_id # uuid of the gw
		self.gw_a3c_pub_key = a3c_pub_key
		self.session_key = session_key # session key computed from the handshake with the A3C_GW
		self.ticket = ticket # the ticket that authenticates the DHM as valid for session establishment
		self.sleep_delta = sleep_delta # time interval between retrying to communicate with the GW in case it failed before
		#self.delta = base64.b64decode(ticket['public'])['expiration_date'] # duration of the session in seconds
		self.r1 = os.urandom(16) # nonce to send to gw
		self.derived_key = None

	def run(self):

		while True:

			#print("# Starting DHM <-> GW session...")
			logger.info("Starting DHM <-> GW session. GW UUID " + self.gw_id)

			req_body = {
				'ticket' : self.ticket,
				'public_key' : base64.b64encode(serializeKey(self.gw_a3c_pub_key)),
				'nonce' : base64.b64encode(self.r1)
			}

			data = parse.urlencode(req_body).encode()
			#req = request.Request(self.gw_addr+"/dhmSessionSetup/", data)
			req = request.Request(GW_ADDR+":"+GW_PORT+"/dhmSessionSetup/", data)

			response = ast.literal_eval(request.urlopen(req).read().decode())

			#print(response)

			r2 = base64.b64decode(response['nonce'])
			# compute derived key K'
			self.derived_key = digestMD5(self.session_key, [self.r1, r2])

			#print("Derived session key (K') with GW")
			#for b in self.derived_key:
			#	print(int(b))

			# validate the sent nonce r1 by decrypting it
			recv_r1 = decryptAES(response['enc_nonce'][0],self.derived_key,response['enc_nonce'][1])
			# encrypt the received nonce r2
			# these last two steps are required to ensure that targets do not create a session 
			# for an attacker using a stolen ticket
			data_final =  { 'nonce' : base64.b64encode(str(encryptAES(self.derived_key, r2)).encode()) } 
			req = request.Request(GW_ADDR+":"+GW_PORT+"/dhmSessionSetup/validation/", parse.urlencode(data_final).encode()) #######################
			request.urlopen(req)
			#response =... # is there a response to this message ? 

			#print("## Session established successfully with the target GW")
			logger.info("Successfully established session with GW UUID: " + self.gw_id)

			# now that the session is established the DHM sends authentication tokens for 
			# the GW to be able to locate the devices and authenticate itself towards them

			# fetch DHs managed by this gateway
			# and generate the respective access token
			logger.info("Fetching DHs data to configure target GW UUID " + self.gw_id)
			managed_dhs = []
			auth_data = {} # authentication data containing the dh ticket and its respective session key with the gw encrypted with gw public key
			for device in dh_list:
				if(device['master_gw_uuid'] == self.gw_id):
					managed_dhs.append(device)
					ticket, key = authTicketGen(device, self.derived_key, self.gw_id)
					gw_pub_key = [g for g in gw_list if g['uuid'] == self.gw_id][0]['pub_key']
					#auth_data[device['uuid']] = [ ticket, encryptRSA(loadKey(gw_pub_key.encode()), key)]
					enc_key, iv = encryptAES(key, self.derived_key)
					#print("AES Encrypted Key")
					#for b in enc_key:
					#	print(int(b))
					#print("IV")
					#for b in iv:
					#	print(int(b))
					#print("KEY used in AES cipher")
					#for b in self.derived_key:
					#	print(int(b))
					auth_data[device['uuid']] = [ ticket, enc_key, iv ]

			d = base64.b64encode(str(auth_data).encode())
			# hmac is generated over the base 64 encode in order to avoid dictionary rearrangements/disparities
			# at the gw endpoint, resulting in different hmacs
			hmac = generateHMAC(self.derived_key, d)

			request_data = {
				'data' : d,
				'signature' : base64.b64encode(hmac)
			}

			logger.info("Sending configuration tickets to target GW UUID " + self.gw_id)
			req = request.Request(GW_ADDR+":"+GW_PORT+"/dhTickets/", parse.urlencode(request_data).encode()) ########################################################
			response = request.urlopen(req).read().decode()

			logger.info(response)

			# thread blocks until receiving any new data 
			#job = self.queue.get()

			#if job == "Session_renew":
		#		# do work
		#	elif job is None:
		#		break
				

			return

			#time.sleep(self.sleep_delta)



# thread responsible for managing the connections and sessions between the DHM and each A3C GW server 
class DHM_A3C_Session(threading.Thread):
	def __init__(self, a3c_uuid, addr, a3c_pub_key, target_gw_id, target_gw_addr, delta, sleep_delta):
		threading.Thread.__init__(self)
		self.a3c_uuid = a3c_uuid # uuid of the a3c server
		self.a3c_addr = addr # url address for the a3c
		self.a3c_pub_key = loadKey(a3c_pub_key) # public key of the a3c
		self.target_gw_id = target_gw_id
		self.target_gw_addr = target_gw_addr
		self.delta = delta # duration of the session in seconds.
		self.sleep_delta = sleep_delta # time interval between retrying to communicate with the A3C in case it failed before
		self.r1 = os.urandom(16)  # nonce to send to A3C
		#self.session_key = None

	def run(self):

		while True:
			try:

				#print("# Fecthing ticket from A3C_GW...")
				logger.info("Fetching ticket from A3C GW with uuid " + self.a3c_uuid)

				req_body = {
				    'id' : self.target_gw_id, # id of the target gateway to be accessed
				    'public_key' : base64.b64encode(server_pub_key_pem),
				    'nonce' : base64.b64encode(encryptRSA(self.a3c_pub_key, self.r1))
				}

				data = parse.urlencode(req_body).encode()
				req = request.Request(self.a3c_addr+"/ticketFetch/", data)
				#response = request.urlopen(req).read().decode()
				response = ast.literal_eval(request.urlopen(req).read().decode())

				#print(response)

				# recover nonce2
				nonce2 = decryptRSA(server_priv_key,base64.b64decode(response['nonce']))

				ticket = response['ticket']
				
				a3c_public_key = base64.b64decode(response['public_key'])

				# compute session key using the retrieved nonce
				session_key = bytes(map(operator.xor, self.r1, nonce2))

				#print("## Ticket fetched successfully!")
				logger.info("Successfully fetched ticket from " + self.a3c_uuid)

				# start DHM-GW connection and session establishment
				dhm_gw_session_queue = Queue()
				dhm_gw_session = DHM_GW_Session(dhm_gw_session_queue,self.target_gw_addr, self.target_gw_id, self.a3c_pub_key, session_key, ticket, self.sleep_delta)
				dhm_gw_session.start()

				return

				#Once the session expires the thread must restart
				# < TODO >
	
			except requests.exceptions.ConnectionError:
				print("# Failed to connect to server \n## Trying again in {} seconds".format(self.sleep_delta))
			#except Exception as exc:
			#    print(exc)
			#    print("# An error ocurred while registering in the server\n## Trying again in {} seconds".format(self.sleep_delta))

			time.sleep(self.sleep_delta)

		return

def main():

	# server password input
	# it will be used to load the server private key
	#server_password = bytes(getpass.getpass(),'utf-8')
	server_password = b"123456789!\"#$%&/()="

	#print("# IOT DHM server starting...")
	logger.info("DHM server starting")

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
	server_pub_key_pem  = loadKeyPEM("rsa_dhm","public",password=None,path="")
	if(server_pub_key_pem == -1):
		logger.critical("Failed to load public key")
		return
	logger.info("Public key loaded successfully")
	global server_priv_key
	server_priv_key = loadKeyPEM("rsa_dhm","private",server_password,path="")
	if(server_priv_key == -1):
		logger.critical("Failed to load private key")
		return
	logger.info("Private key loaded successfully")

	global server_pub_key
	server_pub_key = loadKey(server_pub_key_pem)

	#print("## Keys loaded successfully!")	

	# DHM id is equal to the digest of its public key
	global server_id
	server_id = digestMD5(server_pub_key_pem).hex()
	#print("Server ID: " + server_id)
	logger.info("Server ID : " + server_id)

	## LOGIN procedure complete ## 

	# fetch info of DH this DHM manages from db
	dh_col = db[col_dh]
	global dh_list
	for d in dh_col.find({}):
		dh_list.append({
			'uuid' : d['uuid'],
			'pub_key' : d['pub_key'],
			'ble_addr' : d['ble_addr'],
			'master_gw_uuid' : d['master_gw_uuid']
			})
	#print(dh_list)	

	logger.info("Successfully loaded DHs info from local database")

	# fetch GW info from db
	gw_col = db[col_gw]
	global gw_list
	for d in gw_col.find({}):
		gw_list.append({
			'uuid' : d['uuid'],
			'pub_key' : d['pub_key'],
			'addr' : d['addr'],
			'master_a3c_uuid' : d['master_a3c_uuid']
			})
	#print(gw_list)

	logger.info("Successfully loaded GWs info from local database")

	# fetch A3C GW info from database (address, uuid, public key)
	a3c_gw_col = db[col_a3c_gw]
	a3c_gw_list = []
	for d in a3c_gw_col.find({}):
		a3c_gw_list.append({
			'uuid' : d['uuid'],
			'pub_key' : d['pub_key'],
			'addr' : d['addr']
			})
	#print(a3c_gw_list)

	for device in dh_list:
		target_gw_id = device['master_gw_uuid']
		# get info of device gw
		gw = [g for g in gw_list if g['uuid'] == target_gw_id ]
		gw_a3c_server_uuid = gw[0]['master_a3c_uuid']
		target_gw_addr = gw[0]['addr']
		#print(target_gw_addr)
		# get info of the master a3c of the target gw
		a3c_gw = [a for a in a3c_gw_list if a['uuid'] == gw_a3c_server_uuid][0]
		a3c_gw_address = a3c_gw['addr']
		a3c_gw_pub_key = a3c_gw['pub_key']

		## Start DHM-A3C session. # 1 session <=> 1 thread
		logger.info("Starting session with GW A3C server: " + gw_a3c_server_uuid)
		t = DHM_A3C_Session(gw_a3c_server_uuid, a3c_gw_address, a3c_gw_pub_key.encode(), target_gw_id, target_gw_addr, 3600, 60) 
		t.start()

	## Init REST/web server ## 
	# init tornado web server
	app = make_app()
	app.listen(PORT) 
	#print("Server online and listening")       
	logger.info("Starting web server")
	IOLoop.current().start()


if __name__ == "__main__":
	main()
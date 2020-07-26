import os
import time
import base64
import ast
from urllib import request, parse 
import operator
import threading
import json
import logging
import paho.mqtt.client as mqtt
from queue import Queue

from client_security_module import * 

# logger setup
logging.basicConfig(
level=logging.INFO,
format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
handlers=[
    logging.FileHandler("{0}/{1}.log".format(os.getcwd()+"/logs/", "logger")),
    logging.StreamHandler()
])

logger = logging.getLogger()

# mqtt client setup
client = mqtt.Client()

global_queue = Queue()

# project static values definition since no discovery protocol is implemented

DD_TEMP_UUID = "f17a1fe9d42b711c463cdad54e5db6f0"
DD_LIGHT_UUID = "dab28026b85882feba58b342ab8f592f"

A3C_DD_addr = "http://localhost:2222"
A3C_DD_UUID = "EE3AEEDD1BC30C4D2472D638064151C4"
A3C_DD_PUB_KEY = loadKeyPEM("a3c_dd","public",path="Keys/")

A3C_GW_addr = "http://localhost:8888"
A3C_GW_pub_key = loadKeyPEM("a3c_gw","public",path="Keys/")
A3C_GW_id = "c81306517f41a51b92445538e3406296"

GW_addr = "http://192.168.1.79:1111"
GW_pub_key = loadKeyPEM("gateway","public",path="Keys/")
GW_id = "50433dbaa1de8cf4c381302970dd7f7f"

# global values definition
client_pub_key = None
client_priv_key = None

dds_info = []

def on_connect(client,userdata,flags,rc):
    if(rc==0):
        logger.info("MQTT: New connection established")
    else:
        logger.info("MQTT: Bad connection. Returned code=",rc)

def on_log(client,userdata,level,buf):
    logging.info("MQTT log: " + buf)

def on_message(client,userdata,msg):
    logging.info("MQTT: New message received on topic " + str(msg.topic) + " Payload="+str(msg.payload))

def on_disconnect(client,userdata,rc):
    if(rc!=0):
        logging.info("MQTT: Unexpected disconnection")

def printAppMenu():
	print()
	print("Client application menu")
	print("# 1. Read temperature value")
	print("# 2. Control remote light")
	print("# 0. Exit")
	option = input("> Option: ")
	return option

def loadClientApplication():
	while True:
		option = printAppMenu()
		if(option == '0'):
			break
		if(option == '1'):
			print("## Read temperature value")
			# TODO
		elif(option == '2'):
			print("## Control remote light")
			# TODO
		else:
			print("Invalid option!")

		break



# thread responsible for managing the connections and sessions between the DHM and each GW 
class Client_GW_Session(threading.Thread):
	def __init__(self, gw_addr, gw_id, a3c_pub_key, session_key, ticket, sleep_delta):
		threading.Thread.__init__(self)
		self.gw_addr = gw_addr # url address of the GW
		self.gw_id = gw_id # uuid of the gw
		self.gw_a3c_pub_key = a3c_pub_key
		self.session_key = session_key # session key computed from the handshake with the A3C_GW
		self.ticket = ticket # the ticket that authenticates the Client as valid for session establishment
		self.sleep_delta = sleep_delta # time interval between retrying to communicate with the GW in case it failed before
		self.ticket_pub_decoded = ast.literal_eval(base64.b64decode(ticket['public']).decode())
		self.delta = self.ticket_pub_decoded['expiration_date'] # duration of the session in seconds
		self.r1 = os.urandom(16) # nonce to send to gw
		self.derived_key = None

	def run(self):
		while True:

			#print("# Starting DHM <-> GW session...")
			logger.info("Starting Client <-> GW session. GW UUID " + self.gw_id)

			req_body = {
				'ticket' : self.ticket,
				'public_key' : base64.b64encode(self.gw_a3c_pub_key),
				'nonce' : base64.b64encode(self.r1)
			}

			#print(req_body['public_key'])

			data = parse.urlencode(req_body).encode()
			req = request.Request(self.gw_addr + "/clientSessionSetup/", data)
			try:
				res = request.urlopen(req).read().decode()
				response = ast.literal_eval(res)
			except SyntaxError:
				print("Error: " + res)
				return

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
			req = request.Request(self.gw_addr+"/clientSessionSetup/validation/", parse.urlencode(data_final).encode()) #######################
			response = request.urlopen(req).read()
			#print(response)

			dd_data = ast.literal_eval(response.decode())

			global dds_info
			for host, info in dd_data.items():
				for dd_id, dd_desc in info.items():
					dds_info.append({
						'host_id' : host,
						'dd_id' : dd_id,
						'dd_a3c_id' : dd_desc['a3c_uuid'],
						'dd_pub_key' : dd_desc['pub_key'],
						'dd_api' : dd_desc['api']
					})
					
			dds_info.append(ast.literal_eval(response.decode()))
			#print(dds_info)

			#print("## Session established successfully with the target GW")
			logger.info("Successfully established session with GW UUID: " + self.gw_id)


			## fetch ticket from DD A3C
			#(dd_session_key, client_a3c_dd_ticket) = fetchA3CDDticket(dds_info[0]['dd_id'])
			(dd_session_key, client_a3c_dd_ticket) = fetchA3CDDticket(DD_TEMP_UUID)

			# create session with temperature sensor DD 
			dd_session_r1 = os.urandom(16)
			
			msg = {
				'ticket' : client_a3c_dd_ticket,
				'public_key' : base64.b64encode(A3C_DD_PUB_KEY),
				'nonce' : dd_session_r1
			}

			d = base64.b64encode(str(msg).encode())

			msg_hmac = generateHMAC(self.derived_key, d)

			#print("Data:"+str(d))
			#print("HMAC:"+str(msg_hmac))

			request_data = {
				'data' : d,
				'signature' : base64.b64encode(msg_hmac)
			}

			#msg =  { 'nonce' : base64.b64encode(str(encryptAES(self.derived_key, r2)).encode()) } 
			req = request.Request(self.gw_addr+"/clientDDSessionSetup/", parse.urlencode(request_data).encode())
			response = ast.literal_eval(request.urlopen(req).read().decode())

			print(response)

			# <TODO> add signature to response message and validate it

			clear_nonce2 = response['clear_nonce2'] 
			enc_nonce1_iv = response['enc_nonce1']

			print(clear_nonce2)
			print(enc_nonce1_iv)

			derived_session_key = digestMultipleSHA256([dd_session_r1,clear_nonce2,dd_session_key])

			iv = enc_nonce1_iv[0:16]
			enc_nonce1 = enc_nonce1_iv[16:len(enc_nonce1_iv)]

			decrypted_nonce1 = decryptAES_CBC(enc_nonce1, derived_session_key,iv)

			if(decrypted_nonce1 == dd_session_r1):
				logger.info("Received decrypted nonce matches session nonce")

				enc_nonce2, iv = encryptAES_CBC(clear_nonce2, derived_session_key)

				enc_nonce2_iv = iv + enc_nonce2

				msg = {"enc_nonce2":enc_nonce2_iv}

				req = request.Request(self.gw_addr+"/clientDDSessionSetup/validation/", parse.urlencode(request_data).encode())
				request.urlopen(req)

				# connect to mqtt broker

				client.connect("192.168.1.79")
				client.loop_start()

				# subscribe to desired topic 
				client.subscribe("/ble/"+DD_TEMP_UUID+"/readValue")

				req_data = {"request_type":"subscribe", "target_dd": DD_TEMP_UUID, "dd_action":"readValue", "duration": 10, "delta": 1}
				#req_data = {"request_type:"write", target_dd":"dd_id","dd_action":"turnOn","ack":"yes"}
				req = request.Request(self.gw_addr+"/clientRequest/", parse.urlencode(req_data).encode())
				request.urlopen(req)

				# process response in case of single action interaction and acknowledge flag is set
				# < TODO >

			else:
				print("Error: Received nonce 1 does not match previously sent nonce 1")

			
			# idle
			instruction = global_queue.get()

			time.sleep(self.sleep_delta)

def fetchA3CDDticket(dd_uuid):

	logger.info("Fetching access ticket from A3C DD server " + A3C_DD_UUID)

	# generate nonce R1
	r1 = os.urandom(16)

	req_body = {
		'id' : dd_uuid,
		'public_key' : base64.b64encode(client_pub_key),
		'nonce' : base64.b64encode(encryptRSA(loadKey(A3C_DD_PUB_KEY), r1))
	}

	try: 
		data = parse.urlencode(req_body).encode()
		req = request.Request(A3C_DD_addr+"/ticketFetch/", data)
		response = ast.literal_eval(request.urlopen(req).read().decode())

		# recover nonce2
		nonce2 = decryptRSA(client_priv_key,base64.b64decode(response['nonce']))

		ticket = response['ticket']

		a3c_public_key = base64.b64decode(response['public_key'])

		# compute session key using the retrieved nonce
		session_key = bytes(map(operator.xor, r1, nonce2))

		#print("## Ticket fetched successfully!")
		logger.info("Successfully fetched access ticket from A3C DD server " + A3C_DD_UUID)

		return session_key, ticket

	except requests.exceptions.ConnectionError:
		print("# Failed to connect to server")
	except Exception as exc:
		print(exc)
		print("# An error ocurred while registering in the server")

def fetchA3CGWticket():

	logger.info("Fetching access ticket from A3C GW server " + A3C_GW_id)

	# generate nonce R1
	r1 = os.urandom(16)

	req_body = {
		'id' : GW_id,
		'public_key' : base64.b64encode(client_pub_key),
		'nonce' : base64.b64encode(encryptRSA(loadKey(A3C_GW_pub_key), r1))
	}

	try: 
		data = parse.urlencode(req_body).encode()
		req = request.Request(A3C_GW_addr+"/ticketFetch/", data)
		response = ast.literal_eval(request.urlopen(req).read().decode())

		# recover nonce2
		nonce2 = decryptRSA(client_priv_key,base64.b64decode(response['nonce']))

		ticket = response['ticket']

		a3c_public_key = base64.b64decode(response['public_key'])

		# compute session key using the retrieved nonce
		session_key = bytes(map(operator.xor, r1, nonce2))

		#print("## Ticket fetched successfully!")
		logger.info("Successfully fetched access ticket from A3C GW server " + A3C_GW_id)

		return session_key, ticket

	except requests.exceptions.ConnectionError:
		print("# Failed to connect to server")
	except Exception as exc:
		print(exc)
		print("# An error ocurred while registering in the server")

def loadKeyPair(password):
	global client_priv_key
	client_priv_key = loadKeyPEM("client", "private",password)
	global client_pub_key 
	client_pub_key = loadKeyPEM("client","public")

def main():
	## bootstrap setup ##
	password = b"123456789!\"#$%&/()="

	# load public key pair
	#print("# Loading Client key pair")
	logging.info("Loading client key pair...")
	loadKeyPair(password)

	logging.info("Starting MQTT client")
	client.on_connect = on_connect
	client.on_disconnect = on_disconnect
	client.on_log = on_log
	client.on_message = on_message


	# Client-DD setup process 

	# Step 1 - Fetch Ticket to access GW from GW A3C server

	# for every gateway to be accessed:
	#print("# Fecthing ticket from A3C_GW...")
	session_key, ticket = fetchA3CGWticket()

	# start Client-GW session establishment
	#print("Starting session with target Gateway")
	client_gw_session = Client_GW_Session(GW_addr, GW_id, A3C_GW_pub_key, session_key, ticket, 60)
	client_gw_session.start()

	# < Client-DD > session established

	#loadClientApplication()


if __name__ == "__main__":
	main()
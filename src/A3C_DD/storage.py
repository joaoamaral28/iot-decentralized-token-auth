# function to create and store the cryptographic data to be used by the AAA server
# must only be run once

import pymongo
import os
import datetime

from a3c_dd_security_module import * 

db_client_name = "IOT_A3C_DD_DB"
collection_name = "crypto_info"

col_dd = "dd_info"

# generate public and private keys of the server
# only used to create the .pem files which already exist on the project folder
def generateServerKeyPair(password):
	from cryptography.hazmat.backends import default_backend
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric import rsa

	priv_key = rsa.generate_private_key(public_exponent=655537,key_size=2048,backend=default_backend())
	pub_key = priv_key.public_key()
	pub_key = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	priv_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password))
	
	try:
		with open("private_key_server.pem","w") as file:
			file.write(priv_pem.decode())
		with open("public_key_server.pem","w") as file:
			file.write(pub_key.decode())
	except Exception as exc :
		print("Error occurred while writing key on file")
		print(exc)
		return 

	return


def main():

	# db init
	db_client = pymongo.MongoClient("mongodb://localhost:27017/")	
	db = db_client[db_client_name]
	col = db[collection_name]
	# col.drop()
	
	# password hash+salt storage
	password = b"123456789!\"#$%&/()="
	salt = os.urandom(16)
	key = PBKDF2(password, salt)
	d = {"key":key , "salt":salt }
	x = col.insert_one(d)
	
	for d in col.find({}):
		print(d['key'])
		print(d['salt'])	

if __name__ == "__main__":
	#main()
	#generateServerKeyPair(b"123456789!\"#$%&/()=")


	# ADD DD TO DB 

	db_client = pymongo.MongoClient("mongodb://localhost:27017/")
	db = db_client[db_client_name]
	col = db[col_dd]

	#col.drop()

	info_dd_temp = {
		"uuid" : "f17a1fe9d42b711c463cdad54e5db6f0",
		"public_key": "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvxIfXMBo1qVmGIL41uW\n\
1eZEfBTx6FWblVisCzi0VWBNAmsQbRyvssp1Nd4+Dx5Gkjxww+wgtmzckOtoP/71\n\
Jp3Nlj8rlzBJSx4AzxMB6KyIp56EbAx9K6HxSUFnEfPzPQ9ZyZG2ABd+jMiAYA/K\n\
MD2nu7p1PM5mcd7aL8GpBUL0GE+HxMZtgiJEGlxSbNVdYUu7Wi2kXJruvna0mEia\n\
zI55myEm6xFux4WfPa62YmaVE+ejJrQ6JBS6VIJwhR/oI5n8yffVj4E22GkyG7qD\n\
Uvnd0KuCLyOzeCsvMuD7IXd8SP+A+otutWe5O0T9nT2hNEvxfxAWYZhQHRIOhaU0\n\
IQIDAQAB\n\
-----END PUBLIC KEY-----\n",
		"name" : "temperature sensor",
		"manufacturer" : "Wemos LOLIND32",
		"api" : [ "readValue", "calibrateSensor", "setUnits"],
	}

	info_dd_light = {
		"uuid" : "dab28026b85882feba58b342ab8f592f",
		"public_key":   "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiSGXp45FZTghRw+cpXoK\n\
biW1pkR+d1RB5F8/vnGmNLJW7TZWloqNsaAymvQnK7K40nlFTMhv4lgk+4ABDslp\n\
XbtNI7PySX7RicAIK+t0wsItUZoMr3eA8MxwR9rX40b++aAVAgTqRxxqs9GEHT5K\n\
9i6VZ/OsnjU80Wgd8q3Ykp0J6sb0cg49PH4vT0NE7Wo3Q5PPEvHZ12jXx6dcJ8ti\n\
46ZkHTbe931XabZEatcL7Ya22HekZZ2YQsYopX+3be4cGG+Ox7x7GT068wCbFrMv\n\
wDRcm3Xos9MfhbmTK+2RfH5r9fyi8RzOKl/G5owSlBmxKrBM2SxfxZap+M4sv4cX\n\
twIDAQAB\n\
-----END PUBLIC KEY-----\n",
		"name" : "light actuator",
		"manufacturer" : "Wemos LOLIND32",
		"api" : ["turnOn", "turnOff", "getStatus", "increaseBrightness", "decreaseBrightness"],
	}

	
	# insert document
	x = col.insert_one(info_dd_temp)
	y = col.insert_one(info_dd_light)




	################################################################
	#################### CLIENT REQUEST ############################
	################################################################

	"""

	client_pub_key = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmc5OghowstKC2iGNvsJt\n\
yp0x77uTj+b0ByQ7JnjjzPkaoJ+SWjQkKrMcYhI1RHUlME6ew4QHFZnel6VHtlUd\n\
BMNJRkMMbey//4rZ04CSnyIKKh8rfkBBq5Pqh9iUsHWiRVQyc95VSDnzXd9apPK2\n\
BdGYHItiKJBQC6PltY8wHi3WH9ctWXr/dqhVJXeeKCkUFf7hJSLNSjI2OMH82xe6\n\
4jNfNY1SxLjK32NBrfRiNCb2MbVCYibAz0YT1xMVH65Lgck1xF7kJHAilJ7Ec+6A\n\
s4x84MQIsLQKw6wJnoZcC9OMoLCUD6UobW/D93no9lGSQZ5qWUZ+u8XEoB5rrn2F\n\
ywIDAQAB\n\
-----END PUBLIC KEY-----"

	encoded_client_pub_key = base64.b64encode(client_pub_key.encode())

	client_uuid = digestSHA256(client_pub_key.encode())

	request_id = "1"
	device_id = "1"

	#date = datetime.datetime.now()
	date = "2019-05-16 17:02:39.082262"

	document = encoded_client_pub_key + bytes(client_uuid.hex(),'utf-8') + bytes(request_id,'utf-8') + bytes(device_id,'utf-8') + bytes(date,'utf-8')
	print(document)
	
	print()

	from cryptography.hazmat.backends import default_backend
	from cryptography.hazmat.primitives import serialization

	with open('../Client/private_client.pem', "rb") as key_file:
		priv_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend())
	key_file.close()	

	signature = signRSA(priv_key, document)

	encoded_signature = base64.b64encode(signature)

	#print(encoded_signature)

	print("Request ID: {}".format(request_id))
	print("Client ID: {}".format(client_uuid.hex()))
	print("Client key: {}".format(encoded_client_pub_key))
	print("Device ID: {}".format(device_id))
	print("Date: {}".format(date))
	print("Signature: {}".format(encoded_signature))
	"""

	################################################################
	################# ADD GW TO DATABASE ###########################
	################################################################
"""
	db_client = pymongo.MongoClient("mongodb://localhost:27017/")
	db = db_client[db_client_name]
	col = db["smarthome"]

	
	info_gw1 = {
		"uuid" : "38e998af01b5c8d8287a817211e5e52fb23a3e3bb031c0c1437746d9e148bd17",
		"device_type" : "gateway",
		"public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUF\
PQ0FROEFNSUlCQ2dLQ0FRRUF5WVRUekNKZ1hDd0NJUHVvK2F5bgpROXQrcGRKSWR6QVBudXdYaWpMckQ1bmJPQUh\
xUkwxNmhmeHZCTkhUSWhiaisvanZ0WVNOTUU2SzVRV2FsamV5Ck15MkhqdE55QkFzY2poRkVXVW1TcTUrK09Ick0\
zZGJZMGhoVytYSTIvWXlEWEs4TGs4VzdjbDJua2xvYU1tV0MKK3E0elV5Y1FGMkZUbWhVc1Y5cjNVOEwzSmE5T1l\
HaU5OVTFSSXdQZkVxVE56NU1sV09wYkZkdUwrTXo0YmVxaQpKZ2xlRit5N09LRk5tSEpad25JSjBGUFFTR3o5UzB\
PY25TZGExU0p1TWd0TGoxOVoxUWFxemJlckNLYy9oZnR3CmtCNlFWUjB1UHRrOUtRSWxsVFYvU0s1VUp1RndzYnk\
5YzBGd25tVWdLQ3VSb0FBZ2djVmNmdXVpeUZEZjN3L00KYVFJRENnQ3gKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0\
tCg==",
		"bt_addr" : "B8:27:EB:3E:C9:4B",
		"slave_devices" : [
			{ "uuid" : "8c408678593fff6c916f4177408633c1801fdc3bce650f83edbf43e6c06d79de" } #, "ble_addr": "30:AE:A4:EA:CA:A2" }
		]
	}
"""
	
	# insert document
	#x = col.insert_one(info_gw1)

	# check if gateway exsits 

"""
	gw_id = "38e998af01b5c8d8287a817211e5e52fb23a3e3bb031c0c1437746d9e148bd17"

	if(not col.count_documents({"uuid": gw_id})):
		print("# Invalid registration request!\n## Received gateway ID doest not exists in local database!")
		# self.write("....")
		#return 
	
	print("Gateway ID valid and registered in local database")

	doc = col.find({"uuid" : gw_id}).limit(1)[0]

	slave_devices = doc['slave_devices']

	# get info from gw slave devices
	device_list = []
	device_info = {}
	for device in slave_devices:
		device_uuid = device['uuid']
		if(not col.count_documents({"uuid": device_uuid})):
			print("# Error: IoT slave device ID {}, extracted from gateway document with ID {} not found in collection:{}, document{}!\n## Registration process aborted!".format(device_uuid,gw_id,"smarthome","devices_info"))
			break
			# self.write("....")
			#return 
		doc_device = col.find({"uuid" : device_uuid}).limit(1)[0]
		#print(doc_device)		
		if(doc_device['device_type'] != "host_device"):
			print("# Error:  Mismatch between device type.\n## Device type must be \"host_device\" but \"{}\" was found instead".format(doc_device['device_type']))
			break
			# self.write("...")
			#return
		if(doc_device['master_gateway'] != gw_id):
			print("# Error: Mismatch between slave device and master gateway id\n## Master gateway id {} expected, found id {} instead".format(gw_id,doc_device['master_gateway']))
			break
			# self.write("...")
			#return 

		device_info['uuid'] = device_uuid
		device_info['bt_addr'] = doc_device['bt_addr']
		device_info['driver_list'] = doc_device['driver_list']

		device_list.append(device_info)

		response_code = "OK"

		response = {"code" : "OK", "device_record" : device_list}

		print(device_info)

		#signature = signRSA(server_priv_key, response)

		print("All device information extracted successfully!")
		print("Gateway registered successfully ")

		#self.write(str({"response":response, "signature":signature}))
		#return 
	

	"""
"""
	info_esp1 = {
		"uuid": "8c408678593fff6c916f4177408633c1801fdc3bce650f83edbf43e6c06d79de", 
		"device_type": "host_device", 
		"public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklUQU5CZ2txaGtpRzl3MEJBUUVGQU\
FPQ0FRNEFNSUlCQ1FLQ0FRQlkvZndkRGdGTEN5T3BRNWRJNitZMQorZVZuOUtmQTFHc2F1Q0FzQnlaZkhJYUlrQ\
TNmeCsvNDZtNG5INHM3aGNTandVRVFmTktVSVc2QWpDQ25Ld3NnCmgySVdieER6TkhMK3czR05ramc4RWRBaFJV\
QVhWekFFTFRHSTZiZ1A0eC96ZVhWWENDUTQzZGR6OGZBcmdhUncKNVZKako5WU8zTUh2TzViZFJ2VUk2Tm1PNFp\
FTjBpZW9oUW54NFJZc1Y5SmtWU3RCbm8rODMra0ZyaXFhbDVJVQpja0NaSEV0aXYrZUgwNjAyaXJhYTFSd0Z2cG\
dNRjVWNktJSUxvcXRlVFZaeTJ1dUI0enJDUkdqaDIzZzB5dTZLCnlsZDlQczJkYzV4aXFzZlBCNTUwdjFFcGd2W\
FBZaVEwcnJocXczL1BVSTEzenlWME9vQWN4NHhUUWdTZ3pkb2wKQWdNQkFBRT0KLS0tLS1FTkQgUFVCTElDIEtF\
WS0tLS0tCg==",
		"bt_addr" : "30:AE:A4:EA:CA:A2",
	 	"master_gateway" : "38e998af01b5c8d8287a817211e5e52fb23a3e3bb031c0c1437746d9e148bd17",
		"driver_list" : [ 
			{ 	"id": 1, 
				"type" : "sensor",
				"subtype" : "temperature",
				"actions": [ 
					"readValue()", 
					"calibrateSensor()"
				],
				"description" : {
					"Measurement units" : "Celcius",
					"Operational temperature" : "[-10,50]",
					"Model" : "model xzy",
					"Manufacturer" : "abcdefg"
				}
			},
			{ 	"id": 2,
				"type" : "actuator", 
				"subtype" : "lightbulb",
				"actions" : [
					"turnOn()",
					"turnOff()",
					"increaseBrightness()",
					"decreaseBrightness()"
				],
				"description" : {
					"Measurement units" : "Celcius",
					"Operational range" : "[-10,50]",
					"Model" : "model yrz",
					"Manufacturer" : "gfdsad"
				}
			}
		]

	}

	x = col.insert_one(info_esp1)

	device_id = "8c408678593fff6c916f4177408633c1801fdc3bce650f83edbf43e6c06d79de"
	doc = col.find({"uuid" : device_id}).limit(1)[0]

	print(doc)
	"""
#	db = db_client[db_client_name]
#"	col = db[collection_name]

	# check if any gateway with the received id exists in the local database
#	cursor = col.find({gateway_id: {"$exists": True}}).limit(1)


"""

[ {
	'uuid': '8c408678593fff6c916f4177408633c1801fdc3bce650f83edbf43e6c06d79de', 
	'bt_addr': '30:AE:A4:EA:CA:A2', 
	'driver_list': [
		{ 	'id': 1, 
			'type': 'sensor',
			'subtype': 'temperature',
			'actions': ['readValue()', 'calibrateSensor()'], 
			'description': {'Measurement units': 'Celcius', 'Operational temperature': '[-10,50]', 'Model': 'model xzy', 'Manufacturer': 'abcdefg'}},
		{	'id': 2, 
			'type': 'actuator',
			'subtype': 'lightbulb', 
			'actions': ['turnOn()', 'turnOff()', 'increaseBrightness()', 'decreaseBrightness()'], 
			'description': {'Measurement units': 'Celcius', 'Operational range': '[-10,50]', 'Model': 'model yrz', 'Manufacturer': 'gfdsad'}
		}
	]
  }
]
"""
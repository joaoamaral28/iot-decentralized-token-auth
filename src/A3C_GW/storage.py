import pymongo
import os
import datetime


db_client_name = "IOT_A3C_GW_DB"
col_crypto = "crypto_info"

col_gw = "gw_info"

def main():

	db_client = pymongo.MongoClient("mongodb://localhost:27017/")	
	db = db_client[db_client_name]
				
	# data of the gateways this A3C Server manages
	gw_data = {
		"uuid" : "50433dbaa1de8cf4c381302970dd7f7f",
		"pub_key" : "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYTTzCJgXCwCIPuo+ayn\n\
Q9t+pdJIdzAPnuwXijLrD5nbOAHqRL16hfxvBNHTIhbj+/jvtYSNME6K5QWaljey\n\
My2HjtNyBAscjhFEWUmSq5++OHrM3dbY0hhW+XI2/YyDXK8Lk8W7cl2nkloaMmWC\n\
+q4zUycQF2FTmhUsV9r3U8L3Ja9OYGiNNU1RIwPfEqTNz5MlWOpbFduL+Mz4beqi\n\
JgleF+y7OKFNmHJZwnIJ0FPQSGz9S0OcnSda1SJuMgtLj19Z1QaqzberCKc/hftw\n\
kB6QVR0uPtk9KQIllTV/SK5UJuFwsby9c0FwnmUgKCuRoAAggcVcfuuiyFDf3w/M\n\
aQIDCgCx\n\
-----END PUBLIC KEY-----\n",
		"addr" : "192.168.0.104"
	}
	
	gw_col = db[col_gw]
	#a = gw_col.insert_one(gw_data)
	#gw_col.drop()
	for d in gw_col.find({}):
		print(d['uuid'])
		print(d['pub_key'])
		print(d['addr'])	

if __name__ == "__main__":

	################################################################


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

	main()

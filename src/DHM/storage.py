import pymongo
import os
import datetime


db_client_name = "IOT_DHM_DB"
col_crypto = "crypto_info"

col_a3c_gw = "a3c_gw_info"
col_gw = "gw_info"
col_dh = "dh_info"


def main():

	db_client = pymongo.MongoClient("mongodb://localhost:27017/")	
	db = db_client[db_client_name]
		
	#  data to add to collection A3C_GW_INFO 
	"""
	a3c_gw_data = {
		"uuid" : "c81306517f41a51b92445538e3406296",
		"pub_key" :  "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2LyLcvqaJ9ys4Fx0TT7r\n\
EA24WOVKrc3ZxV/jHS6x4e/WSqnubUc5le9wCCypfflgAJBNRyChJoWBPEZwVE9v\n\
vvdky3Kf5LTtDWnVD0WC4pmQh9NWw6DD5U+Br3cxRyPeMvxjczppGlXmpcAr6XDT\n\
056gaQIiD4HNtnshb6caNmsb3ve0CUjnKuKqoWNFS+L+HrIuJZYEgjIczsFzwsKM\n\
DIn7fMyKE4T4xD/Wd2sDZ+JsjSTxomB5rMfs/jvRwAeE4lCXJ+nFrCttbB2SANfa\n\
7tOwBVanL0R/JieS5tcwMJs0leAC0zD461s+xGFqE0RwW/oDvcwBTGvKBS+dGC8J\n\
DQIDCgCx\n\
-----END PUBLIC KEY-----\n",
		"addr" : "http://localhost:8888"
	}
	"""
	#a3c_gw_col = db[col_a3c_gw]
	#a = a3c_gw_col.insert_one(a3c_gw_data)
	# a3c_gw_col.drop()
	
	#for d in a3c_gw_col.find({}):
	#	print(d['uuid'])
	#	print(d['pub_key'])
	#	print(d['addr'])	

		
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
		"addr" : "192.168.0.104",
		"master_a3c_uuid" : "c81306517f41a51b92445538e3406296"
	}
	
	gw_col = db[col_gw]
	a = gw_col.insert_one(gw_data)
	#gw_col.drop()
	for d in gw_col.find({}):
		print(d['uuid'])
		print(d['pub_key'])
		print(d['addr'])	
		print(d['master_a3c_uuid'])

	# info of the devices the DHM manages
	# this data is persistent, that is, it exsits in the database permanently
	# unlike the gw and a3c data which is inserted in the database during the
	# discovery protocol
	'''
	dh_data = {
		"uuid" : "4b97c0a6358f5da943afdcd747a7c86c",
		"pub_key" : "-----BEGIN PUBLIC KEY-----\n\
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBY/fwdDgFLCyOpQ5dI6+Y1\n\
+eVn9KfA1GsauCAsByZfHIaIkA3fx+/46m4nH4s7hcSjwUEQfNKUIW6AjCCnKwsg\n\
 h2IWbxDzNHL+w3GNkjg8EdAhRUAXVzAELTGI6bgP4x/zeXVXCCQ43ddz8fArgaRw\n\
5VJjJ9YO3MHvO5bdRvUI6NmO4ZEN0ieohQnx4RYsV9JkVStBno+83+kFriqal5IU\n\
ckCZHEtiv+eH0602iraa1RwFvpgMF5V6KIILoqteTVZy2uuB4zrCRGjh23g0yu6K\n\
yld9Ps2dc5xiqsfPB550v1EpgvXPYiQ0rrhqw3/PUI13zyV0OoAcx4xTQgSgzdol\n\
AgMBAAE=\n\
-----END PUBLIC KEY-----\n",
		"ble_addr" : "30:AE:A4:EA:C2:C2",
		"master_gw_uuid" : "50433dbaa1de8cf4c381302970dd7f7f",
		"drivers" : None # idk if this field is necessary => info of the drivers running on the device
	}

	dh_col = db[col_dh]
	a = dh_col.insert_one(dh_data)
	#gw_col.drop()
	for d in dh_col.find({}):
		print(d['uuid'])
		print(d['pub_key'])
		print(d['ble_addr'])
		print(d['master_gw_uuid'])	
	'''

	"""
	d = {"key":key , "salt":salt }
	x = col.insert_one(d)
	
	for d in col.find({}):
		print(d['key'])
		print(d['salt'])	
	"""


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

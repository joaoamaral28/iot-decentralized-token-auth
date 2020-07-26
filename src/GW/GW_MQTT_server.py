
import paho.mqtt.client as mqtt

import argparse
import random

import time

parser = argparse.ArgumentParser()

parser.add_argument('-H', '--host', required=False, default="localhost")
parser.add_argument('-d', '--debug', required=False,action='store_true')
parser.add_argument('-q', '--qos', required=False, type=int,default=0)
parser.add_argument('-t', '--topic', required=False, default="house/temperature")

args, unknown = parser.parse_known_args()

'''
class MQTTBroker():
	#TODO
'''

def on_connect(mqttc, obj, flags, rc):
    print("connect rc: " + str(rc))

def on_message(mqttc, obj, msg):
    print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))

def on_publish(mqttc, obj, mid):
    print("mid: " + str(mid))

def on_subscribe(mqttc, obj, mid, granted_qos):
    print("Subscribed: " + str(mid) + " " + str(granted_qos))

def on_log(mqttc, obj, level, string):
	print(string)

def main():

	mqttc = mqtt.Client(client_id="gw_broker")#, clean_session=True, userdata=None,transport="websockets")

	mqttc.on_message = on_message
	mqttc.on_connect = on_connect
	mqttc.on_publish = on_publish
	mqttc.on_subscribe = on_subscribe
	mqttc.on_log = on_log

	host = "192.168.0.108"
	port = 1883

	print("Connecting to "+host+" port: "+str(port))

	mqttc.connect(host)

	# topics are created based on available sensors
	# sensors are added after scanning for new devices

	topic1 = "house/temperature"
	topic2 = "house/C02"
	topic3 = "house/humidity"
	# topic4 = "house/kitchen/C02"

	topics = [topic1, topic2, topic3]

	#mqttc.loop_start()

	value = random.randint(1,101)

	print("Publishing in " + topic1 + ", value:" + str(value))

	infot = mqttc.publish(topic1, value)

	#infot.wait_for_publish()

	#	mqttc.loop_end()

	'''
	while True:
		value = random.randint(1,101)
		print("Publishing in " + topic1 + ", value:" + str(value))
		infot = mqttc.publish(topic1, value)
		infot.wait_for_publish()
		time.sleep(5)
		
		for topic in topics:
			value = random.randint(1,101)
			print("Publishing in " + topic + ", value:" + str(value))
			infot = mqttc.publish(topic, value)
			infot.wait_for_publish()
			print("CONA")
			time.sleep(2)
		time.sleep(5)
		'''

if __name__ == "__main__":
	main()
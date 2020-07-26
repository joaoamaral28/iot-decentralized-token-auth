import paho.mqtt.client as mqtt
import time

broker = "192.168.1.79"

client = mqtt.Client()

def  on_connect(client,userdata,flags,rc):
    if(rc==0):
        print("Connection successfull")
        #client.subscribe("/test_topic/")
    else:
        print("Bad connection. Return code=",rc)

def on_log(client,userdata,level,buf):
    print("log: " + buf)

def on_message(client,userdata,msg):
    print("New message received on topic " + str(msg.topic) + " Payload="+str(msg.payload))

def on_disconnect(client,userdata,rc):
    if(rc!=0):
        print("Unexpected disconnection")

client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_log = on_log
client.on_message = on_message

client.connect(broker)
client.loop_start()

time.sleep(50)

#client.loop_stop()
#client.disconnect()

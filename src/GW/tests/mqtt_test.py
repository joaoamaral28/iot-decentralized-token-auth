import paho.mqtt.client as mqtt
import time

client = mqtt.Client()

def on_subscribe(client, userdata, mid, granted_qos):
    print("ON_SUBSCRIBE")
    print(client)
    print(userdata)
    print(mid)
    print(granted_qos)

def on_connect(client,userdata,flags,rc):
    if(rc==0):
        print("connected OK")
        print(client)
    else:
        print("Back connection. Returned code=",rc)

def on_log(client, userdata, level, buf):
    print("log: "+buf)

client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_log=on_log

client.connect("localhost")
client.loop_start()

client.publish("/test_topic/","OLA")

time.sleep(10)

client.loop_stop()
client.disconnect()

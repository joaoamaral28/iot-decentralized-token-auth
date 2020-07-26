#import bluepy
import time
import os
import datetime
import json
import base64
import ast
from urllib import request, parse 
import requests
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler

#from bluepy.btle import Scanner, DefaultDelegate

from subprocess import Popen, PIPE
from threading import Thread

from gw_security_module import * 

cmd = ['sudo','timeout','-s','SIGINT','5s','hcitool','lescan']

esp = {}

# Flag signaling the gateway has registered successfully in the home controller server (IoT AAA)
registered = False

# listening port
PORT = 1111

# AAA server uri
# for now it will be static, meaning known to the GW before the boot process
AAA_SERVER = "http://localhost:8888"

# global variables 
gw_id = None
gw_priv_key = None
gw_pub_key_pem = None
gw_pub_key = None
server_pub_key = None
server_pub_key_pem = None
device_record = None

class MainHandler(RequestHandler):
    def get(self):
        self.write("Hello")
        #devices = ["Device 1", "Device 2", "Device 3"]
        #self.render(os.getcwd() + "/template/index.html", devices=devices)

class AccessHandler(RequestHandler):
    def post(self):
        print("POST message received \n" + str(self.request) + "\n")

        if(not registered):
            print("# Gateway needs to be registered in AAA server in order to process client requests")
            #self.write()
            return

        #if( device_uuid not in slave_devices):
        # print("# Unkown device uuid")

        #if(device_uuid not in online_slave_devices):
        # print("# Device not yet online or is out of range!")

        token = self.get_body_argument('token')
        signature = self.get_body_argument('signature') 
        nonce = self.get_body_argument('nonce')

        print("Token: {}".format(token))
        print("Signature: {}".format(signature))
        print("Nonce: {}".format(nonce))

        # validate message signature ???

        # GW needs to check if it has connection 

        # init QUEUE to hold client requests 


class MCUDiscoveryThread(Thread):
    # delta => amount of time in between thread cycles (seconds). Default 1h
    # cmd_timeout => amount of time before exiting ble device scanning (seconds). Default 5s
    def __init__(self,delta=3600, cmd_timeout=5):
        Thread.__init__(self)
        if(cmd_timeout < 1 or cmd_timeout > 20):
            raise ValueError("Invalid command timeout. Must be integer between 1 and 20")
        elif(delta < 60 or delta> 86400):
            raise ValueError("Invalid thread cycle interval. Must be integer between 60 and 86400")
        
        self.cmd_timeout = cmd_timeout;
        self.delta = delta
        self.cmd = ['sudo', 'timeout', '-s', 'SIGINT', str(cmd_timeout)+'s', 'hcitool', 'lescan']
        self.startup=True

    def run(self):
        while True:
            print("Searching for BLE compatible devices...")
            old = len(esp)
            p = Popen(self.cmd, stdin=PIPE, stdout=PIPE)
            for l in p.stdout:
                s = l.decode('utf-8')
                if 'ESP32_' in s:
                    #print(s)
                    s = s.split(" ")
                    b_addr = s[0]
                    name = s[1][:-1]
                    if b_addr not in esp.values():
                        print("New BLE device found")
                        print("Name: {}, Addr: {} ".format(name,b_addr))
                        esp[name] = b_addr

            if(len(esp)==0 and self.startup==True):
                print("No ESP devices BLE compatible found at startup!")
            elif(self.startup==True):
                self.startup=False
                print("Found {} ESP devices BLE compatible at startup".format(len(esp)))
                print()
                print("Name\t\tBLE address")
                for k,v in esp.items():
                    print(k + "\t" + v)
            else:
                print("No additional devices found...")
            print("\nNext discovery in {}\n".format(str(datetime.timedelta(seconds=self.delta))))
            time.sleep(self.delta)
"""
class SlaveDeviceScan(Thread):
    # delta => amount of time in between thread cycles (seconds). Default 1h
    # cmd_timeout => amount of time scanning for devices. Default 10s
    def __init__(self,delta=3600, delta_scan=5):
        Thread.__init__(self)
        if(delta_scan < 1 or delta_scan > 30):
            raise ValueError("Invalid command timeout. Must be integer between 1 and 30")
        elif(delta < 60 or delta> 86400):
            raise ValueError("Invalid thread cycle interval. Must be integer between 60 and 86400")
        
        self.delta_scan = delta_scan;
        self.delta = delta
        #self.cmd = ['sudo', 'timeout', '-s', 'SIGINT', str(cmd_timeout)+'s', 'hcitool', 'lescan']
        #self.startup=True
        self.scanner = Scanner().withDelegate(self.ScanDelegate())

    class ScanDelegate(DefaultDelegate):
        def __init__(self):
            DefaultDelegate.__init__(self)

        def handleDiscovery(self,dev,isNewDev,isNewData):
            if(isNewDev):
                print("Discovered device: {}".format(dev.addr))
            elif(isNewData):
                print("Received new data from {}".format(dev.addr))

    def run(self):
        while True:
            device_list = self.scanner.scan(self.delta_scan)
            for device in device_list:
                # Received Signal Strength Indicator
                print("Device %s (%s), RSSI=%d dB" % (device.addr, device.addrType, device.rssi ))
                for (adtype,desc,value) in device.getScanData():
                    print("\t%s = %s" % (desc, value))

"""
def make_app():
    urls = [
        ("/", MainHandler),
        ("/accessRequest/", AccessHandler)
    ]
    return Application(urls, debug=True)

def loadKeys():
    # load gw public key
    global gw_pub_key_pem
    gw_pub_key_pem = loadKeyPEM('gateway','public')
    if(not gw_pub_key_pem):
        print("## Gateway public key load failed!")
        return 0
    global gw_pub_key
    gw_pub_key = loadKey(gw_pub_key_pem)
    # load gw private key
    global gw_priv_key
    gw_priv_key = loadKeyPEM('gateway','private',password=b"qwertyuiop",path="")
    if(not gw_priv_key):
        print("## Gateway private key load failed!")
        return 0
    # load aaa server public key
    global server_pub_key
    server_pub_key_pem = loadKeyPEM('server','public')
    if(not server_pub_key_pem):
        print("## Server public key load failed!")
        return 0
    global server_pub_key
    server_pub_key = loadKey(server_pub_key_pem)

    return 1

def main():
    '''
    # create key pair 
    #storeKeyPEM("gateway",pub_key,"public")

    # QUE PASSWORD USAR ??
    # A GW supostamente vai ser plug-n-play não sendo necessário qualquer tipo de input de configuração inicial
    #  por parte do utilizador certo ? Nesse caso a PW vai ter de ser uma string embutida neste código
    # por enquanto uso pw em string mas no futuro rever e arranjar uma melhor alternativa
    # < TOOD >
    password = b"qwertyuiop"
    storeKeyPEM("gateway",priv_key,"private",password)
    '''
    #########################################################################################################

    #thr_discovery = SlaveDeviceScan()
    #thr_discovery.start()
    #return

    print("# Starting...")

    # load keys from local folder files
    if(not loadKeys()):
        print("## Key load step failed! Aborting operation... ")
        return

    print("# Successfully loaded all keys from file")

    # gateway id is equal to the digest of its public key
    global gw_id
    gw_id = digestSHA256(gw_pub_key_pem).hex()

    document = bytes(gw_id,'utf-8') + gw_pub_key_pem 

    #print(document)

    # register on AAA home server
    req_sign = signRSA(gw_priv_key, document)
    
    req_body = {
        'id' : gw_id,
        'public_key' : base64.b64encode(gw_pub_key_pem),
        'signature' : base64.b64encode(req_sign)
    }
   
    data = parse.urlencode(req_body).encode()

    # GW needs to register in the home AAA server before proceeding any further
    # block until gateway receives registration confirmation from the AAA server
    req_delta = 30 # polling for connection with the server every delta seconds
    while True:
        try:

            req = request.Request(AAA_SERVER+"/registrationRequest/", data)
            #response = request.urlopen(req).read().decode()
            response = ast.literal_eval(request.urlopen(req).read().decode())

            response_sign = response['signature']
            response_msg = response['response']

            # validate server signature
            # this must be done first in order to verify the message authenticity 
            if(not validateRSA(server_pub_key, response_sign, str(response_msg).encode())):
                print("# Response signature invalid! Discarding received response")
                continue

            print("#Message signature is valid!")

            response_code = response_msg['Code']

            if(response_code == "OK"):
                print("## Server registration successful!")
                
                # Access message content & decode base64
                enc_device_record = base64.b64decode(response_msg['device_record'])
                iv = base64.b64decode(response_msg['iv'])
                key = base64.b64decode(response_msg['dec_key'])

                # Decode simmetric key
                dec_key = decryptRSA(gw_priv_key,key)

                # Decrypt record
                dec_record = decryptAES(enc_device_record,dec_key,iv)
                
                global device_record
                device_record = json.loads(dec_record)
                #print(device_record)
                for device in device_record:
                    print(device_record[device])

                global registered
                registered = True
                print("# Registration on control server was successful!")

                #thr_discovery = SlaveDeviceScan()
                #thr_discovery.start()

                break

            if(response.response_code == "SIGNATURE_INVALID"):
                print("# Registration on control server failed!\n## Invalid signature!")
                # < TODO > Handle response 
                return
            if(response.response_code == "UNKNOWN_ID"):
                print("# Registration on control server failed!\n## Unknown gateway ID!")
                # < TODO > Handle response
                return
        except requests.exceptions.ConnectionError:
            print("# Failed to connect to server \n## Trying again in {} seconds".format(req_delta))
        except Exception as exc:
            print(exc)
            print("# An error ocurred while registering in the server\n## Trying again in {} seconds".format(req_delta))

        time.sleep(req_delta)

    # GW SCANS FOR THE KNOWN DEVICES THAT HE RECEIVED FROM THE AAA SERVER
    # OR WAITS UNTIL RECEIVING PAIRING REQUEST FROM THE DEVICES AND THEN CREATE THE CONNECTION ? 
    # < TODO > 

    # launch discovery thread
    # it checks for new BLE compatible devices with the name prefix "ESP32" every delta seconds 
    #t = MCUDiscoveryThread()
    #t.start()

    # init tornado web server
    print("# Web server starting...")
    app = make_app()
    app.listen(PORT)        
    IOLoop.current().start()




if __name__ == "__main__":
    main()

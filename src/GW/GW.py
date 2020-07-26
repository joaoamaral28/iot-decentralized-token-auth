import time
import os
import datetime
import json
import base64
import ast
import logging
import threading
from urllib import request, parse 
import requests
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler
from ast import literal_eval
from queue import Queue

import paho.mqtt.client as mqtt

from bluepy.btle import Scanner, DefaultDelegate, Peripheral
from gw_security_module import * 

import ble_message_pb2

#logger setup 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}/{1}.log".format(os.getcwd()+"/logs/","logger")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

# mqtt client setup

client = mqtt.Client()

cmd = ['sudo','timeout','-s','SIGINT','5s','hcitool','lescan']

esp = {}

# Flag signaling the gateway has registered successfully in the home controller server (IoT AAA)
registered = False

# listening port
PORT = 1111

# global variables 
gw_id = None
gw_priv_key = None
gw_pub_key_pem = None
gw_pub_key = None
gw_a3c_pub_key = None
gw_a3c_pub_key_pem = None
device_record = None

client_sessions = {}
configured_devices = []
dd_list = {}

# list containing the inter-thread communication queues
q_list = {}

MAX_MSG_SIZE = 514 # maximum data transported (in bytes) in each write operation
HEADER_SIZE = 4

gw_a3c_id = None

notification_buffer = b''
stream_ready = False

# < TODO > Update for a dictionary structure containing each session GW <-> DHM matching it with its session key
derived_session_key = None

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

class PeripheralDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)
                    
    def handleNotification(self,cHandle,data):
        logger.info("Notification reveived!")
        #print("Data: {}".format(data))
        #print(data.hex())
        global notification_buffer
        if(data[0] == 48 and data[1]==49): # single frame
            logging.info("Single notification received")
            #print("Single notification received!")
            notification_buffer = data[2:-1]
            #print(notification_buffer)
            #message = ble_message_pb2.BLEmessage()
            #message.ParseFromString(data[2:-1])
            #print(message.ListFields())
        elif(data[1]!=49): # multiple frames processing
            #print("Processing stream notification messsage n%s" % chr(data[0]))
            logging.info("Processing stream notification message n%s" % chr(data[0]))
            notification_buffer = notification_buffer + data[2:]
        elif(data[1]==49): # last stream message
            #print("Processing last stream notification message n%s" % chr(data[0]))
            logging.info("Processing last stream notification message(n%s)" % chr(data[0]))
            notification_buffer = notification_buffer + data[2:]
            global stream_ready
            stream_ready = True

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self,dev,isNewDev,isNewData):
        if(isNewDev):
            print("Discovered device: {}".format(dev.addr))
        elif(isNewData):
            print("Received new data from {}".format(dev.addr))

def mqtt_on_subscribe(client, userdata, mid, granted_qos):
    return

def mqtt_on_connect(client,userdata,flags,rc):
    if(rc==0):
        logger.info("MQTT: New connection established")
    else:
        logger.info("MQTT: Bad connection state. Returned code=",rc)

def mqtt_on_log(client,userdata,level,buf):
    logger.info("MQTT log:"+buf)

# Serializes input data into ble_message protocol buffer specified format
# as defined in ble_message.proto
def serializeData(data, format, nonce=None):

    message = ble_message_pb2.BLEmessage()
    header = message.header
    payload = message.payload

    if(format=="auth_ticket"):
        header.msg_type = header.AuthTicket
        message.header.CopyFrom(header)
        auth_ticket = payload.auth_ticket
        auth_ticket.secret = data['secret']
        #print(data['secret'])
        auth_ticket.pub = data['public']
        #print(data['public'])
        auth_ticket.signature = data['signature']
        #print(data['signature'])
        auth_ticket.auth_nonce = nonce
    elif(format=="driver_auth_ticket"):
        header.msg_type = header.DriverAuthTicket
        message.header.CopyFrom(header)
        auth_ticket = payload.auth_ticket
        auth_ticket.secret = data['secret']
        auth_ticket.pub = data['public']
        auth_ticket.signature = data['signature']
        auth_ticket.auth_nonce = nonce
    elif(format=="access_request"):
        header.msg_type = header.DeviceAccessRequest
        message.header.CopyFrom(header)
        request = payload.request
        request.target_uuid = data['target_dd']
        request.action = data['dd_action']
        request.delta = int(data['delta'])
    elif(format=="access_response"):
        header.msg_type = header.DeviceAccessResponse
        # < TODO >
    else:
        print("[Error] Invalid header type")
        return

    message.payload.CopyFrom(payload)

    return message.SerializeToString()
    

def dataFragment(data):
    #fragment data in MAX_MSG_SIZE-HEADER_SIZE (510) byte chunks
    fragments = [ data[i:i+(MAX_MSG_SIZE-HEADER_SIZE)] for i in range(0,len(data),MAX_MSG_SIZE-HEADER_SIZE)]
    
    return fragments

def dataFragment1(data):
    fragments = [ data[i:i+(MAX_MSG_SIZE - 2)] for i in range(0,len(data),MAX_MSG_SIZE - 2)]
    return fragments

def scanBLEdevices(delta_scan):

    #print("# Scanning for BLE compatible devices....")
    logger.info("Scanning for nearby BLE compatible devices...")

    scanner = Scanner().withDelegate(ScanDelegate())

    device_list = scanner.scan(delta_scan)
    for device in device_list:
        # Received Signal Strength Indicator
        #print("Device %s (%s), RSSI=%d dB" % (device.addr, device.addrType, device.rssi ))
        logger.info("Device %s (%s), RSSI=%d dB" % (device.addr, device.addrType, device.rssi ))
        for (adtype,desc,value) in device.getScanData():
            logger.info("\t%s = %s" % (desc, value))
            #print("\t%s = %s" % (desc, value))

    return device_list

class DH_GW_Session(threading.Thread):

    def __init__(self, dh_id, ticket, key, ble_device, handler, q, q_out):
        threading.Thread.__init__(self)
        self.dh_id = dh_id
        self.auth_ticket = ticket
        self.session_key = key
        self.device = ble_device
        #self.scanner = Scanner().withDelegate(self.ScanDelegate())
        self.nonce = os.urandom(16)
        self.handler = handler
        self.q = q
        self.q_out = q_out
        
    def run(self):
        while True:
            logger.info("Starting session with DH " + self.device.addr)
            #dh_ble_addr = self.auth_ticket['public']['dh_addr']
                
            # connect to DH view BLE

            # fetch public authentication characteristic

            # if characteristic read value indicates DH is ready to start a session 
            # then send the DHM received authentication ticket + nonce1
            # Receive session confirmation from DH
            # Additionally the DH also sends nonce2 + nonce1 encrypted with derived session key

            # Validate encrypted nonce and send nonce2 encrypted with derived session key 
            
            scan_data = self.device.getScanData()
            device_name = scan_data[2][2]
            auth_service_uuid = scan_data[4][2]
            #print(device_name)
            #print(auth_service_uuid)
            #for (adtype,desc,value) in device.getScanData(): 
            #    print("\t%s = %s" % (desc, value))


            try:
                device = Peripheral(self.device.addr)
                device.setMTU(520) # max value is 520 bytes per BLE transference
                device.setDelegate(PeripheralDelegate())
                #print("Successfully connected to device host " + self.device.addr)
                logger.info("Successfully connected to DH " + self.device.addr)
                auth_service = device.getServiceByUUID(auth_service_uuid)
                auth_char = auth_service.getCharacteristics()[0] # authentication service has a single characteristic to perform read/write transfers
        
                # set characteristic CCCD descriptor to 0x01 x00 
                # needed to receive notifications from DH
                # as specified in bluetooth RFC
                auth_char_cccd = auth_char.getHandle() + 1
                device.writeCharacteristic(auth_char_cccd, b"\x01\x00")
                    
                #read authentication characteristic state
                auth_char_val = auth_char.read()
                if(auth_char_val.decode() == '0x15'): # BLE_CHAR_AUTH_REQ
                    #print("# Device host ready to receive authentication ticket")
                    logger.info("DH " + self.device.addr + "ready to receive authetication ticket")

                    s_auth_ticket = serializeData(self.auth_ticket, "auth_ticket", self.nonce)  
                    #print(s_auth_ticket.hex())

                    #for byte in s_auth_ticket:
                    #    print(int(byte))

                    #for b in self.auth_ticket['secret']:
                    #    print(int(b))
                
                    #s_auth_ticket = str(self.auth_ticket).replace("b\'","")
                    #print(s_auth_ticket)
                    #msg_header = "0x50" # authentication signalling header
                    
                    #if((len(s_auth_ticket)+HEADER_SIZE) > MAX_MSG_SIZE ):
                    if(len(s_auth_ticket) + 2 > MAX_MSG_SIZE):
                        #print("Message size exceeds maximum capacity. Fragmenting data...")
                        logger.info("Authentication ticket message exceeds link maximum capacity (" + str(MAX_MSG_SIZE) +") Data will be fragmented")
                        #fragments = dataFragment(s_auth_ticket)
                        fragments = dataFragment1(s_auth_ticket)
                        #print(fragments)
                        for idx in range(0,len(fragments)):
                            if(idx == len(fragments)-1):
                                ending_flag = 1
                            else:
                                ending_flag = 0
                            sequence_no = idx + 1
                            msg = bytes([sequence_no]) + bytes([ending_flag]) + fragments[idx]
                            #print(msg)
                            #print(bytes([sequence_no]))

                            #msg = msg_header.encode() + frag.encode()
                            #print(msg)
                            #print(len(msg))
                            auth_char.write(msg)
                            time.sleep(0.5) # interval between writes in order to avoid unexpected delays
                        
                        #print("Authentication ticket sent to target DH successfully!")
                        logger.info("Authentication ticket message sent to target DH " + self.device.addr+ " successfully")
                        # wait for DH response notification
                        #print("Waiting for DH response...")
                        logger.info("Waiting for DH "+self.device.addr+" response notification")
                        while True:
                            if(device.waitForNotifications(1.0)):
                                #print(notification_buffer)
                                response = ble_message_pb2.BLEmessage()
                                response.ParseFromString(notification_buffer)
                                #print(response.ListFields())
                                #print(response.header.msg_type)
                                global notification_buffer
                                notification_buffer = b''

                                # process response 
                                if(response.header.msg_type == ble_message_pb2.Header.MessageType.NonceExchange):
                                    #print("Nonce exchange msg received!")
                                    logger.info("Nonce exchange message received")
                                    encrypted_nonce1 = response.payload.nonce_exc_msg.enc_nonce
                                    clear_nonce2 = response.payload.nonce_exc_msg.clear_nonce
                                        
                                    # generate derived session key using received nonce2
                                    derived_session_key = digestMultipleSHA256([self.nonce, clear_nonce2, self.session_key])
                                    #print("Derived session key K'")
                                    #for b in derived_session_key:
                                    #    print(int(b))

                                    iv = encrypted_nonce1[0:16]
                                    enc_nonce1 = encrypted_nonce1[16:len(encrypted_nonce1)]
                                    
                                    #print("Init Vector")
                                    #for b in iv:
                                    #    print(int(b))
                                    #print("ENC NONCE1")
                                    #for b in enc_nonce1:
                                    #    print(int(b))
                                    #print("TOTAL")
                                    #for b in encrypted_nonce1:
                                    #    print(int(b))

                                    # decrypt nonce1
                                    decrypted_nonce1 = decryptAES_CBC(enc_nonce1, derived_session_key, iv)

                                    #print("DECRYPTED NONCE1")
                                    #for b in decrypted_nonce1:
                                    #    print(int(b))
                                    #print("CLEAR NONCE1")
                                    #for b in self.nonce: 
                                    #    print(int(b))
                                    # check if it matches session nonce (self.nonce)
                                    if(decrypted_nonce1 != self.nonce):
                                        print("# Error: Received nonce does not match session nonce. Could be due to faulty encryption or decryption.\n## Restarting session setup...")
                                        # < TODO > Handle session restart 
                                    else:
                                        logger.info("Received decrypted nonce matches session nonce")
                                        #print("Decrypted nonce matches session nonce!")
                                        # encrypt received nonce2 and send it to finalize the nonce exchange and session setup protocol
                                        enc_nonce2, iv = encryptAES_CBC(clear_nonce2, derived_session_key)
                                        # join ciphertext and iv in the same buffer and serialize to be ready for transmission
                                        #print("clear nonce2")
                                        #for b in clear_nonce2:
                                        #    print(int(b))
                                        #print("enc nonce2")
                                        #for b in enc_nonce2:
                                        #    print(int(b))
                                        #print("I V")
                                        #for b in iv:
                                        #    print(int(b))

                                        enc_nonce2_iv = iv + enc_nonce2
                                    
                                        reply = ble_message_pb2.BLEmessage()

                                        header = reply.header
                                        payload = reply.payload

                                        header.msg_type = header.NonceExchange
                                        reply.header.CopyFrom(header)

                                        nonce_exc = payload.nonce_exc_msg
                                        nonce_exc.enc_nonce = enc_nonce2_iv

                                        reply.payload.CopyFrom(payload)

                                        s_reply = reply.SerializeToString()
                                        
                                        #for b in s_reply:
                                        #    print(int(b))

                                        auth_char.write(bytes([0,1]) + s_reply)

                                        logging.info("Session with DH "+self.device.addr+" established succsessfully")

                                        ## Session setup is now complete!
                                        # (does the DH reports a response to this last message ?)
                                        
                                        logging.info("Waiting for DH "+self.device.addr+" installed drivers information...")
                                
                                        while(stream_ready==False):
                                            device.waitForNotifications(10)
                                        
                                        dds_info = ble_message_pb2.BLEmessage()
                                        dds_info.ParseFromString(notification_buffer)
                                        notification_buffer = b''
                                        #print(dds_info.ListFields())

                                        if(dds_info.header.msg_type == ble_message_pb2.Header.MessageType.DriversInfo):
                                            logging.info("Received DDs info from DH " + self.device.addr)

                                            # add info do dds list
                                            #print(dds_info.payload.drivers_info_msg.driver_info)
                                            global dd_list
                                            dd_list[self.dh_id] = {}
                                            for dd in dds_info.payload.drivers_info_msg.driver_info:
                                                dd_id = digestMD5(dd.public_key).hex()
                                                dd_dict = {}
                                                dd_dict['pub_key'] = dd.public_key 
                                                dd_dict['api'] = dd.api_description
                                                dd_dict['a3c_uuid'] = dd.a3c_dd_uuid
                                                        

                                                dd_list[self.dh_id].update({ dd_id: dd_dict})

                                            global configured_devices
                                            configured_devices.append(self.device.addr)

                                            #print(dd_list)

                                            #self.handler.write("DH "+ self.dh_id +" (address " + self.device.addr+") successfully configured") 
                                            msg = {'dh_uuid': self.dh_id, 'status': 'OK'}
                                            
                                            #print(self.handler.request.protocol+"://"+self.handler.request.remote_ip+":7777"+"/dhSessionConfirm/")

                                            req = request.Request(self.handler.request.protocol+"://"+self.handler.request.remote_ip +":7777"+ "/dhSessionConfirm/", parse.urlencode(msg).encode())

                                            request.urlopen(req)
                                            #process attributes and build MQTT topics!
                                        elif(dds_info.header.msg_type == ble_message_pb2.Header.MessageType.ErrorMessage):
                                            print("Error!")
                                        else:
                                            print("Unknown message received")

                                #elif(response.header.msg_type == ble_message_pb2.Header.MessageType.ErrorMessage):
                                # < TODO > Handle error & session restart
                                else:
                                    print("# Error: Unknown message header received!\n # Restarting session setup...")
                                    # < TODO > Handle error & session restart
                                    return

                            break
            
                    else:
                        print("Packet does not exceed maximum capacity")
                        sequence_no = '0'
                        ending_flag = '1'
                    #auth_char.write(msg)
                #else:
                    # catch other responses here
                    # such as if device n

                while(True):
                    logging.info("Waiting for further instructions...")
                    (instruction, data) = self.q.get() # wait for further instructions
                    #process received instruction after unblocking
                    if(instruction == "clientSessionRequest"):
                        logging.info("Client session request received")
                    
                        # retrieve and encode data 

                        decoded_data = literal_eval(base64.b64decode(data).decode())

                        ticket = decoded_data['ticket']
                        a3c_dd_public_key = decoded_data["public_key"]
                        nonce1 = decoded_data['nonce']

                        # serialize message
                        data_serial = serializeData(ticket,"driver_auth_ticket", nonce1)

                        if(len(data_serial) + 2 > MAX_MSG_SIZE):
                            #print("Message size exceeds maximum capacity. Fragmenting data...")
                            logger.info("Driver authentication ticket message exceeds link maximum capacity (" + str(MAX_MSG_SIZE) +"). Data will be fragmented...")
                            frags = dataFragment1(data_serial)

                            for idx in range(0,len(frags)):
                                if(idx == len(frags)-1):
                                    ending_flag = 1
                                else:
                                    ending_flag = 0
                                sequence_no = idx + 1
                                msg = bytes([sequence_no]) + bytes([ending_flag]) + frags[idx]
                        
                                print(msg)
                                #print(len(msg))
                                auth_char.write(msg)
                                time.sleep(0.5) # interval between writes in order to avoid unexpected delays
                       
                            #print("Authentication ticket sent to target DH successfully!")
                            logger.info("Client authentication ticket sent to target DH " + self.device.addr+ " successfully")
                            # wait for DH response notification
                            #print("Waiting for DH response...")
                        else:
                            print("Message does not exceed maximum link capacity")
                            # Handle message sending here
                            # < TODO >
                        

                        # wait for notification from DH
                        logger.info("Waiting for DH notification...")
                        if(device.waitForNotifications(1.0)):
                            reponse = ble_message_pb2.BLEmessage()
                            response.ParseFromString(notification_buffer)
                            notification_buffer = b''

                            # process response 
                            if(response.header.msg_type == ble_message_pb2.Header.MessageType.NonceExchange):
                                #print("Nonce exchange msg received!")
                                logger.info("Nonce exchange message received")
                                encrypted_nonce1 = response.payload.nonce_exc_msg.enc_nonce
                                clear_nonce2 = response.payload.nonce_exc_msg.clear_nonce

                                # < TODO >

                                msg = {"enc_nonce1":encrypted_nonce1, "clear_nonce2":clear_nonce2}
                                self.q_out.put(msg)

                            elif(response.header.msg_type == ble_message_pb2.Header.MessageType.ErrorMesssage):
                                print("Error!")
                            else:
                                print("Unknown message received!")

                        # send reply back to respective client!


                    if(instruction == "clientRequestSubscribe"):
                        logger.info("Subscribe client request received")

                        target_dd = data["target_dd"]
                        dd_action = data["dd_action"]
                        duration = data["duration"]
                        delta = data["delta"]

                        # serialize request 
                        serial_data = serializeData({"target_dd":target_dd, "dd_action":dd_action, "delta":delta},"access_request") 
                        # write to dh characteristic
                        auth_char.write(bytes([0]) + bytes([1]) + serial_data)
                        # process notification stream and publish data to corresponding topic
                        timeout = time.time() + int(duration)
                      
                        logger.info("Waiting for DH response...")
                        if(device.waitForNotifications(2.0)):
                            print("AAAAA")
                            response = ble_message_pb2.BLEmessage()
                            response.ParseFromString(notification_buffer)
                            notification_buffer = b''
                            print(response)
                            client.publish("/ble/"+target_dd+"/"+dd_action, ord(response.payload.response.response))
                        
                        """
                        while time.time < timeout:
                            if(device.waitForNotifications(1.0)):
                                reponse = ble_message_pb2.BLEmessage()
                                response.ParseFromString(notification_buffer)
                                notification_buffer = b''

                                client.publish("ble/"+target_dd+"/"+dd_action,response.value)
                        """

            except Exception as exc:
                print(exc)

            finally: 
                print("finally")
                #device.disconnect()
            

            return

class MainHandler(RequestHandler):
    def get(self):
        self.write("Hello")
        #devices = ["Device 1", "Device 2", "Device 3"]
        #self.render(os.getcwd() + "/template/index.html", devices=devices)

# handler used by clients to access a particular device host (DH)
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

class clientSessionHandler(RequestHandler):
    def post(self):

        #print("# Session request received from Client")
        logger.info("Session request received from Client")

        ticket = literal_eval((self.get_body_argument('ticket')))
        pub_key = base64.b64decode(self.get_body_argument('public_key'))
        nonce = base64.b64decode(self.get_body_argument('nonce'))
        
        # Check if received GW a3c public key matches the uui
        if(digestMD5(pub_key).hex() != gw_a3c_id):
            error_msg = "## Error: Received public key does not match this Gateway A3C server public key!"
            #print(error_msg)
            logger.critical("Received public key does not match the A3C GW public key ")
            self.write(error_msg)                                      
            return
        #print("## Public key of gateway a3c is valid!")
        logger.info("Public key of GW A3C is valid")

        # validate ticket signature
        public = base64.b64decode(ticket['public'])
        m = ticket['secret'] + bytes(public)
        #print(m)
        if(not validateRSA(gw_a3c_pub_key, ticket['signature'], m)):
            #print("## Error: Session ticket signature is invalid!")
            logger.info("Session ticket signature is invalid")
            self.write("Invalid ticket signature!")
            return
        
        #print("## Session ticket signature is valid!")
        logger.info("Session ticket signature is valid")

        # Recover key K from the ticket secret part with GW priv key
        session_key = decryptRSA(gw_priv_key, ticket['secret'])

        # Generate random nonce r2
        r2 = os.urandom(16)

        global client_sessions
        # compute K' = digest(K,r1,r2)
        derived_session_key = digestMD5(session_key, [nonce, r2])
        
        client_sessions[0] = derived_session_key
        
        #print("Derived session key (K') with Client")
        #for b in derived_session_key:
        #    print(int(b))

        response = {
            'nonce' : base64.b64encode(r2),
            'enc_nonce' : encryptAES(derived_session_key, nonce)
        }

        self.write(str(response))

        return
    
class clientSessionValidationHandler(RequestHandler):
    def post(self):

        #print("# Session validation message received from client")
        logging.info("Session validation message received from client")

        enc_r2 = base64.b64decode(self.get_body_argument('nonce'))

        r2 = literal_eval(enc_r2.decode())

        ciphertext = r2[0]
        iv = r2[1]

        #print("ciphertext")
        #print(ciphertext)
        #print("iv")
        #print(iv)

        # decrypt nonce 
        dec_r2 = decryptAES(ciphertext,client_sessions[0], iv)

        #print("## Session validated and established successfully with Client!")
        logging.info("Session validated and established successfully with client")

        # Gateway responds to client with the DDs info it obtained
        # from the DH upon establishing a valid session with it

        logging.info("Sending known DDs information to client...")

        self.write(str(dd_list))
        
        return

class dhTicketHandler(RequestHandler):
    def post(self):

        #print("# Received authentication tickets from DHM server")
        logger.info("Authentication tickets received from DHM server")

        data = self.get_body_argument('data')
        hmac = base64.b64decode(self.get_body_argument('signature'))

        # validate message hmac 
        if(not validateHMAC(derived_session_key,str(data).encode(),hmac)):
            #print("## Invalid message HMAC!")
            logger.critical("Received message HMAC is invalid")
            self.write("ERROR: HMAC validation failed")
            return

        #print("## Valid message HMAC!")
        logger.info("Received message HMAC is valid")

        decoded_data = literal_eval(base64.b64decode(data).decode())

        #print(decoded_data)

        # scan for online ble devices
        #online_devices = scanBLEdevices(30)
        #print(online_devices)


        # match the online devices with the ones received from the DHM
        # by extracting their BLE addresses from the ticket public part
        # Note that the ticket public part is encoded in base64 format
        # necessary in order to maintain its dictionary order, which is
        # required in order to generate the original data from which the 
        # ticket signature was generated, that is, the concatenation between
        # the ticket secret and public parts 
        
        # as long the ticket is valid, connection attempts will be made
        # when the ticket becomes invalid, the gw no longer tries to search for such device
        # until receives new indication from its master DHM
        for k,v in decoded_data.items():
            ticket = v[0]
            #print(ticket)
            #print("Key inside ticket (K)")
            #for b in v[1]:
            #    print(int(b))
            #print("IV")
            #for b in v[2]:
            #    print(int(b))
            key = decryptAES(v[1], derived_session_key, v[2])
            #print("KEY used in AES cipher")
            #for b in derived_session_key:
            #    print(int(b))
            #print("Key after AES decrypt")
            #for b in key:
            #    print(int(b))
            online_devices = scanBLEdevices(5) 
            dh_addr = literal_eval(base64.b64decode(ticket['public']).decode())['dh_addr']
            #print(dh_addr)
            for device in online_devices:
                if(device.addr == dh_addr.lower()):
                    q_in = Queue()
                    q_out = Queue()
                    global q_list
                    q_list.update({k:(q_in, q_out)})
                    s = DH_GW_Session(k, ticket, key, device, self, q_in, q_out)
                    s.start()
                    #s.join()

            # if certain device was not found it is marked as unavailable
            # and will be searched for again after a specified <delta> time inverval
            # of its first search and inbetween attempts
            # < TODO > 
            # create a single thread for handling the undiscovered devices
            
        return

class dhmSessionValidationHandler(RequestHandler):
    def post(self):
        #print("# Session validation message received from DHM server")
        logger.info("Session validation request received from DHM server")

        enc_r2 = base64.b64decode(self.get_body_argument('nonce'))

        r2 = literal_eval(enc_r2.decode())

        ciphertext = r2[0]
        iv = r2[1]

        # decrypt nonce 
        dec_r2 = decryptAES(ciphertext,derived_session_key, iv)

        #print("## Session validated and established successfully!")
        logging.info("Session established with DHM successfuly")

        # only sends response if error occurrs ????
        # self.write("OK")

        # here the response could be the first message of the ticket fetching protocol 
        # O -> A3C : Ko+. UUIDt, 

        return


class dhmSessionHandler(RequestHandler):
    def post(self):

        #print("# Session request received from DHM server")
        logger.info("Session request received from DHM server")

        ticket = literal_eval((self.get_body_argument('ticket')))
        pub_key = base64.b64decode(self.get_body_argument('public_key'))
        nonce = base64.b64decode(self.get_body_argument('nonce'))
        
        # Check if received GW a3c public key matches the uui
        if(digestMD5(pub_key).hex() != gw_a3c_id):
            error_msg = "## Error: Received public key does not match this Gateway A3C server public key!"
            #print(error_msg)
            logger.crititcal("Received GW A3C public key does not match")
            self.write(error_msg)                                      
            return
        logger.info("Received GW A3C public key is valid")
        #print("## Public key of gateway a3c is valid!")

        # validate ticket signature
        public = base64.b64decode(ticket['public'])
        m = ticket['secret'] + bytes(public)
        if(not validateRSA(gw_a3c_pub_key, ticket['signature'], m)):
            #print("## Error: Session ticket signature is invalid!")
            logger.critical("Received session ticket signature is invalid")
            self.write("Invalid signature!")
            return

        #print("## Session ticket signature is valid!")
        logger.info("Session ticket signature is valid")

        # Recover key K from the ticket secret part with GW priv key
        session_key = decryptRSA(gw_priv_key, ticket['secret'])

        # Generate random nonce r2
        r2 = os.urandom(16)

        
        # The derived key will be handled as a global variable for now
        # Need to be changed for a global dictionary or other data structure 
        # and map each key to each DHM establishing a session with the gw
        # while also being accessed in a global scope
        # < TODO >
        global derived_session_key
        # compute K' = digest(K,r1,r2)
        derived_session_key = digestMD5(session_key, [nonce, r2])
        #print("Derived session key (K') with DHM")
        #for b in derived_session_key:
        #    print(int(b))

        response = {
            'nonce' : base64.b64encode(r2),
            'enc_nonce' : encryptAES(derived_session_key, nonce)
        }

        self.write(str(response))

        return

class clientDDSessionHandler(RequestHandler):
    def post(self):

        logger.info("Session request received from client")

        data = self.get_body_argument("data")
        hmac= base64.b64decode(self.get_body_argument("signature"))
        
        # validate message hmac 
        if(not validateHMAC(client_sessions[0],str(data).encode(),hmac)):
            #print("## Invalid message HMAC!")
            logger.critical("Received message HMAC is invalid")
            self.write("ERROR: HMAC validation failed")
            return

        logger.info("Received message HMAC is valid")

        l = list(q_list.values())
        l[0][0].put(("clientSessionRequest", data))

        # fetch dh associated with the target dd
        """
        for dh,info in dd_list.items():
            for dd_id, dd_desc in info.items():
                if(dd_id==data['ticket']['public']['dd_id']):
                   q_list[dh].put("clientSessionRequest")
                    break    
        """
        # wait for dd response message 
        response = l[0][1].get()

        # reply back to the client 

        self.write(str(response))
        
        return

class clientDDSessionValidationHandler(RequestHandler):
    def post(self):
        print("Client DD Session Validation Handler")

        # Send nonce exchange message to DH in order to validate the session establishment
        # < TODO >



class clientRequestHandler(RequestHandler):
    def post(self):
        logger.info("Received new client request")

        request_type = self.get_body_argument('request_type')
        target_dd = self.get_body_argument('target_dd')
        action = self.get_body_argument('dd_action')

        # get corresponding queue of dh device that hosts the target dd
        # < TODO >

        if(request_type == "subscribe"):
            instruction = "clientRequestSubscribe"
            duration = self.get_body_argument('duration')
            delta = self.get_body_argument('delta')

            data = {"request_type":request_type, "target_dd": target_dd, "dd_action":action, "duration": duration, "delta": delta}

            l = list(q_list.values())
            l[0][0].put(("clientRequestSubscribe", data))

        elif(request_type == "write"):
            instruction = "clientRequestWrite"
            ack = self.get_body_argument('ack')
            data = {"request_type":request_type, "target_dd": target_dd, "dd_action":action, "ack": ack}
            l = list(q_list.values())
            l[0][0].put(("clientRequestSubscribe", data))
            if(ack=="yes"):
                response = l[0][1].get()
                self.write(str(response))
        else:
            print("Unknown request received")
    

def make_app():
    urls = [
        ("/", MainHandler),
        ("/accessRequest/", AccessHandler),
        ("/dhmSessionSetup/", dhmSessionHandler),
        ("/dhmSessionSetup/validation/", dhmSessionValidationHandler),
        ("/dhTickets/", dhTicketHandler),
        ("/clientSessionSetup/", clientSessionHandler),
        ("/clientSessionSetup/validation/", clientSessionValidationHandler),
        ("/clientDDSessionSetup/", clientDDSessionHandler),
        ("/clientDDSessionSetup/validation/", clientDDSessionValidationHandler),
        ("/clientRequest/", clientRequestHandler)
    ]
    return Application(urls, debug=True)

def loadKeys():
    # load gw public key
    global gw_pub_key_pem
    gw_pub_key_pem = loadKeyPEM('gateway','public')
    if(not gw_pub_key_pem):
        #print("## Gateway public key load failed!")
        logger.critical("Failed to load public key")
        return 0
    logger.info("Public key loaded successfully")
    global gw_pub_key
    gw_pub_key = loadKey(gw_pub_key_pem)
    # load gw private key
    global gw_priv_key
    gw_priv_key = loadKeyPEM('gateway','private',password=b"qwertyuiop",path="")
    if(not gw_priv_key):
        #print("## Gateway private key load failed!")
        logger.critical("Failed to load private key")
        return 0
    logger.info("Private key loaded successfully")
    # load aaa server public key
    global gw_a3c_pub_key_pem
    gw_a3c_pub_key_pem = loadKeyPEM('a3c_gw','public')
    if(not gw_a3c_pub_key_pem):
        #print("## Gateway A3C server public key load failed!")
        logger.critical("Failed to load gw a3c public key")
        return 0
    logger.info("GW A3C public key loaded successfully")
    global gw_a3c_pub_key
    gw_a3c_pub_key = loadKey(gw_a3c_pub_key_pem)

    return 1

def main():

    #print("# Starting...")
    logger.info("GW starting")

    logger.info("Loading local keys")
    # load keys from local folder files
    if(not loadKeys()):
        #print("## Key load step failed! Aborting operation... ")
        return

    #print("# Successfully loaded all keys from file")

    # gateway id is equal to the digest of its public key
    global gw_id
    gw_id = digestMD5(gw_pub_key_pem).hex()

    global gw_a3c_id
    gw_a3c_id = digestMD5(gw_a3c_pub_key_pem).hex()

    # init mqtt client
    logger.info("GW MQTT Client starting...")
    client.on_connect = mqtt_on_connect
    client.on_subscribe = mqtt_on_subscribe
    client.on_log = mqtt_on_log

    client.connect("localhost")
    client.loop_start()

    # init tornado web server
    #print("# Web server starting...")
    logger.info("GW Web server starting")
    app = make_app()
    app.listen(PORT)        
    IOLoop.current().start()


if __name__ == "__main__":
    main()

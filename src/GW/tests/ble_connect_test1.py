import bluepy.btle
import json
import time
from bluepy.btle import Scanner, DefaultDelegate, Peripheral

from struct import *

DH_ADDRESS = "30:AE:A4:EA:C2:C2"
"""
auth_ticket = {'secret': b'#\xe7gQ\xc4O\xa2\xee\x9e\xd6\x89\x85=i%\xe9hB\x05k\xaa\xe5\xf6k\xa3<\xe7\xee\xb6T;\xd3\xfb }f\xe1+["\x82\xdf,mG\xe0\xec_\x9cpN\xc4 WH\xc2\x9b\x89F\xe5!\x8cge\x9d2y$\x0b\x1b\xcb\x08\x8b\xc4\xf3\xe6\xd6\xd3\x96p\x855~\xb6\xc6\xbf\xc7\x9eZ\xb3\x121\xb33\x06v29\xb4b\x83]j\xfeK\n{\x12[!\xcc\xd8\xc5\xd09V\x8c]\x81\xe4\x0b\xb8\xef\xf1i\x8a;\x9c:\xc2\xe4r\xa5\x9e\x1d\x9b~k\xde\x7f]\xfa\xa2\x85\x9d\xfe\xc5&\x84FZ\x9b\xe8\x9b\x103[\t\x9c\x89\xa9\x87\x0bj\xa5*z\xc4\xea\xf9\x19H\xad\xb1\xb5.\x02\xba\xdbw]{1\xd7\xbb\xbdM|\xd2\xbb\xbae95FA\x94 \r\x18 \xf38\xdb\xd1\xe3\n\xd7\x0eO1\xfbi\xbd!!\x83\xc6`F\xb7W$\x97{$J\xdc\xc3\x14\xfd\xbeWC_\x0c\xceKem\x80\x80\xa7iq\xf8Mk\xff\xf2\x0b\xb6\x17\xa4\xcc\xa4', 'public': {'dh_id': '4b97c0a6358f5da943afdcd747a7c86c', 'dh_addr': '30:AE:A4:EA:C2:C2', 'owner_id': '50433dbaa1de8cf4c381302970dd7f7f', 'access_rights': 'Rx', 'ticket_lifetime': 3600}, 'signature': b'\xbe\xdao\xfc\x19i\n\xf8wS?u\x00\x1b\t\x89*0Qc=\xf6\xc8\xd1\x8cf\x9b\x1f\xafM\xf3\x90\x18VZi\x98\xea\x0e\x1b\r\x80\x03\x04\xd2"\xde|f\x9d\x03\xef\xd4\xd5T\xb0F_\x06\xad\x04m\xca\xd1\xcbA\x12/\xe0a[\xf1\xcf\xe7.\x03l~\xfc{\xca\xf7\x8d\x1a\xa8\xa5w\xa7\xa1\xf6\xca\xf5\x93\xaa\x08\x8d\xe33\n\xff.\xee\xc5*D\x9b/|dj\xa7\x8fC\xa9\xf1m\xa6\xc2o\xd4\xa2&\xac\xdd\xed\x92\x1f,\xb3b\x07\xd7\xc6{\x16\x8b\xd8\x86\xc5\xbbH\x1a\xf9(\xa2\x8f/J\xb8\xa6r\x8bZ\xf21\x92\x86H\x97\xf4\xed\xe1_\xad\xdb\x1c+B\x82\xf0\xc6\xdd\x10\xa75\xe4]\x19\x8f\xe5>\x9e\x98\x85\xc0\xddA\xde\x1e\xcev\xcd\xcb\x8ek{In\x9b\x08\x02R\xc6P\x88\xf0\xc4\xa8\x95\x06;Y\x1f\xbd7\xad4a\xea\xc8F\x8a\xde\xed\xb9\xb0\x83\xe5*\xa2\x0c\x06\xf5\\i\xe2xw\x83\xd0\x90cV)\x85q`@\x8f\x9a\xcdUd\xd9`\x08'}
"""

auth_ticket = {'secret': b'AyPvD0nh8YBrSL0NIlq3ZZJVevPlwNbh8XA2SDSKVxtNZQZBFoxP9Pu0j9VvPYtWjvGQItTfT5f+VSTNat9pym4RCfm/ZGOwNbK5bai0oaBzo3uOxQq7YcNsm+K4SBrCQXmiW1i4QsTVV57guPu00JfisvygYStm/zvhv3/QVDxopkqTrgEClo8Mplb4hcl0Owmy0sOYB6HaLssy6sqkDI4fbJxHp/WQRR8msloDpXWe3PMHPIgrUaJZBf6dzi11+tECsh2z0iK43rd8sR8BldiiMyj9rNQyI0flZew3Yv11Pw2XTAtyI7l3Rha4jVKyeRsOXTijQj9BOyq0WXK0tQ==', 'public':b'eydkaF9pZCc6ICc0Yjk3YzBhNjM1OGY1ZGE5NDNhZmRjZDc0N2E3Yzg2YycsICdkaF9hZGRyJzogJzMwOkFFOkE0OkVBOkMyOkMyJywgJ293bmVyX2lkJzogJzUwNDMzZGJhYTFkZThjZjRjMzgxMzAyOTcwZGQ3ZjdmJywgJ2FjY2Vzc19yaWdodHMnOiAnUngnLCAndGlja2V0X2xpZmV0aW1lJzogMzYwMH0=', 'signature': b'PI8TZ+QerykaT+bl+Nnync2X0jGARf8uDSyfHtuLb+ZU7A2onA9uUku6+OjX+pLe8nHCCcy//N/ffN8hHg1xG8bWKwWpMcyZT0VP2WuJaQ6xG1vRaa4nAG8EsVXrq7Svloe3OqqKyzkY8U7I8Bcru5Bk101wPm0ewu/OAJMESq+amuIEA7SmasCuE3bDiVL3NwAYTVvL8lnsAm7D228dEiHRwrm9ppAkMQ5LBP4E/7wQXlcZdk2KV/S+m3v5wfikedxjxmo19CuQzcL8r91LAykgI2cuI+HNi0p6sMZjTCCMnmBPG0FfcXglYlK9lIhz0X8qbd1N4XvO0qbBoGFNZg=='}

class PeripheralDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)
                    
    def handleNotification(self,cHandle,data):
        print(data)

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self,dev,isNewDev,isNewData):
        if(isNewDev):
            print("Discovered device: {}".format(dev.addr))
        elif(isNewData):
            print("Received new data from {}".format(dev.addr))

MAX_MSG_SIZE = 514 # maximum size of data transported in each write operation
HEADER_SIZE = 4

def dataFragment(data):
    #fragment data in MAX_MSG_SIZE-HEADER_SIZE (510) byte chunks
    fragments = [ data[i:i+(MAX_MSG_SIZE-HEADER_SIZE)] for i in range(0,len(data),MAX_MSG_SIZE-HEADER_SIZE)]
    
    return fragments

def main():
     
    scanner = Scanner().withDelegate(ScanDelegate())

    device_list = scanner.scan(5) # scan for 5 seconds
    for device in device_list:
        if(device.addr.lower() == DH_ADDRESS.lower()):
            print("Target device host discovered!")
            # RSSI = Received Signal Strength Indicator
            print("Device %s (%s), RSSI=%d dB" % (device.addr, device.addrType, device.rssi ))  
            scan_data = device.getScanData()
            device_name = scan_data[2][2]
            auth_service_uuid = scan_data[4][2]
            print(device_name)
            print(auth_service_uuid)
            #for (adtype,desc,value) in device.getScanData(): 
            #    print("\t%s = %s" % (desc, value))

    try:
        device = Peripheral(DH_ADDRESS)
        device.setMTU(520) 
        device.setDelegate(PeripheralDelegate())
        print("Successfully connected to device host")
        auth_service = device.getServiceByUUID(auth_service_uuid)
        auth_char = auth_service.getCharacteristics()[0]

        # read authentication characteristic state
        auth_char_val = auth_char.read()
        #print(auth_char_val)
        if(auth_char_val.decode() == '0x15'): # BLE_CHAR_AUTH_REQ
            print("# Device host ready to receive authentication ticket")
        #auth_ticket = { 'sercret':1, 'public':2 ,'signature':3}
        #auth_ticket = "{'secret': qqqqqqqqqqqqqqaaaaaaaaaaaaaaaaaaaaaaaaaassssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss, 'public': {'dh_id' : uuid, 'dh_addr' : addr, 'owner_id' : gw_id, 'access_rights' : 'Rx', 'ticket_lifetime': 3600},'signature': sig}"
        s_auth_ticket = str(auth_ticket).replace("b\'","")
        print(s_auth_ticket)
        
        msg_header = "0x50"
        #msg_payload = str(auth_ticket).encode()
        #msg = msg_header.encode() + msg_payload
        #msg = msg[0:100]
        if((len(s_auth_ticket)+HEADER_SIZE) > MAX_MSG_SIZE ):
            print("Message size exceeds maximum capacity. Fragmenting data...")

            fragments = dataFragment(s_auth_ticket)
            for frag in fragments:
                msg = msg_header.encode() + frag.encode()
                print(msg)
                #print(len(msg))
                auth_char.write(msg)
                time.sleep(0.5)
        else:
            print("Packet does not exceed maximum capacity")
        #auth_char.write(msg)
        #else:
            # catch other responses here
            # such as if device not ready, wait and do authentication later
            # < TODO > 
        #    print("# Something went wrong...")

        """
        while True:
            if p.waitForNotifications(1.0):
                # handleNotification() was called
                continue
             print "Waiting..."
            # Perhaps do something else here
        """


    finally:
        device.disconnect()

if __name__ == "__main__":
    main()

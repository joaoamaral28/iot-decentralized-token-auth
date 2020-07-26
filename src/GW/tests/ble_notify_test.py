import bluepy.btle
import json
import time
from bluepy.btle import Scanner, DefaultDelegate, Peripheral

from struct import *

DH_ADDRESS = "30:AE:A4:EA:C2:C2"

class PeripheralDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)
                    
    def handleNotification(self,cHandle,data):
        print("Notification received!")
        print(data)

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self,dev,isNewDev,isNewData):
        if(isNewDev):
            print("Discovered device: {}".format(dev.addr))
        elif(isNewData):
            print("Received new data from {}".format(dev.addr))

def main():
     
    scanner = Scanner().withDelegate(ScanDelegate())

    device_list = scanner.scan(5) # scan for 5 seconds
    for device in device_list:
        if(device.addr.lower() == DH_ADDRESS.lower()):
            print("Target device host discovered!")
            # RSSI = Received Signal Strength Indicator
            #print("Device %s (%s), RSSI=%d dB" % (device.addr, device.addrType, device.rssi ))  
            scan_data = device.getScanData()
            device_name = scan_data[2][2]
            auth_service_uuid = scan_data[4][2]
            #print(device_name)
            #print(auth_service_uuid)
            #for (adtype,desc,value) in device.getScanData(): 
            #    print("\t%s = %s" % (desc, value))


    device = Peripheral(DH_ADDRESS)
    device.setMTU(520) 
    device.setDelegate(PeripheralDelegate()) 
    print("Successfully connected to device host")
    auth_service = device.getServiceByUUID(auth_service_uuid)
    auth_char = auth_service.getCharacteristics()[0]
    # read authentication characteristic state
    
    #print(auth_char.valHandle)
    auth_char_cccd = auth_char.getHandle() + 1
    print("CCCD 0x%X" % auth_char_cccd)


    device.writeCharacteristic(auth_char_cccd, b"\x01\x00")
    
    #device.withDelegate(PeripheralDelegate())

    auth_char_val = auth_char.read()
    print(auth_char_val)
    #if(auth_char_val == 0):
    ##    print("Zero")

    # wait for server confirmation as a notification message
    while True:
        if(device.waitForNotifications(1.0)):
            print("new notification from server")
            continue
        print("Waiting...")

if __name__ == "__main__":
    main()

import ble_message_pb2
import os

ble_message = ble_message_pb2.BLEmessage()

# header
header = ble_message.header

header.msg_type = header.AuthTicket

#print(dir(ble_message.header))

ble_message.header.CopyFrom(header)

# payload
payload = ble_message.payload
auth_ticket = payload.auth_ticket

auth_ticket.private = b"private"
auth_ticket.public = b"public"
auth_ticket.signature = b"signature"
auth_ticket.auth_nonce = os.urandom(32)

ble_message.payload.CopyFrom(payload)

print(ble_message)

msg_bytes = ble_message.SerializeToString()

print(msg_bytes)

# serializes data into a readable format by the DH using protocol buffers
def serializeData(data, format):
  message = ble_message_pb2.BLEmessage()
  header = message.header

  if(format=="AuthTicket"):
    header.msg_type = header.AuthTicket
  elif(format=="AccessRequest"):
    header.msg_type = header.DeviceAccessRequest
  elif(format=="AccessResponse"):
    header.msg_type = header.DeviceAccessResponse
  else:
    print("[Error] Unknown header type")

  message.header.CopyFrom(header)

  payload = message.payload
  auth_ticket = payload.auth_ticket

  auth_ticket.private = b"private"
  auth_ticket.public = b"public"
  auth_ticket.signature = b"signature"

  message.payload.CopyFrom(payload)

  return message.SerializeToString()


def deserializeData(data):
  return None

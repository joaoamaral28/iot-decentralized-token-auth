# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ble_message.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ble_message.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x11\x62le_message.proto\"@\n\nBLEmessage\x12\x17\n\x06header\x18\x01 \x02(\x0b\x32\x07.Header\x12\x19\n\x07payload\x18\x02 \x02(\x0b\x32\x08.Payload\"\xca\x01\n\x06Header\x12%\n\x08msg_type\x18\x01 \x02(\x0e\x32\x13.Header.MessageType\"\x98\x01\n\x0bMessageType\x12\x0e\n\nAuthTicket\x10\x01\x12\x11\n\rNonceExchange\x10\x02\x12\x0f\n\x0b\x44riversInfo\x10\x03\x12\x17\n\x13\x44\x65viceAccessRequest\x10\x04\x12\x18\n\x14\x44\x65viceAccessResponse\x10\x05\x12\x0c\n\x08\x45rrorMsg\x10\x06\x12\x14\n\x10\x44riverAuthTicket\x10\x07\"\xfa\x01\n\x07Payload\x12*\n\x0b\x61uth_ticket\x18\x01 \x01(\x0b\x32\x15.AuthenticationTicket\x12,\n\rnonce_exc_msg\x18\x02 \x01(\x0b\x32\x15.NonceExchangeMessage\x12-\n\x10\x64rivers_info_msg\x18\x03 \x01(\x0b\x32\x13.DriversInfoMessage\x12\"\n\x08response\x18\x04 \x01(\x0b\x32\x10.MessageResponse\x12 \n\x07request\x18\x05 \x01(\x0b\x32\x0f.MessageRequest\x12 \n\terror_msg\x18\x06 \x01(\x0b\x32\r.ErrorMessage\"D\n\x0eMessageRequest\x12\x13\n\x0btarget_uuid\x18\x01 \x02(\t\x12\x0e\n\x06\x61\x63tion\x18\x02 \x02(\t\x12\r\n\x05\x64\x65lta\x18\x03 \x01(\x05\"8\n\x0fMessageResponse\x12\x13\n\x0btarget_uuid\x18\x01 \x02(\t\x12\x10\n\x08response\x18\x02 \x02(\t\"Z\n\x14\x41uthenticationTicket\x12\x0e\n\x06secret\x18\x01 \x02(\x0c\x12\x0b\n\x03pub\x18\x02 \x02(\x0c\x12\x11\n\tsignature\x18\x03 \x02(\x0c\x12\x12\n\nauth_nonce\x18\x04 \x01(\x0c\">\n\x14NonceExchangeMessage\x12\x11\n\tenc_nonce\x18\x01 \x02(\x0c\x12\x13\n\x0b\x63lear_nonce\x18\x02 \x01(\x0c\"=\n\x0c\x45rrorMessage\x12\x12\n\nerror_code\x18\x01 \x02(\x0c\x12\x19\n\x11\x65rror_description\x18\x02 \x01(\t\"6\n\x12\x44riversInfoMessage\x12 \n\x0b\x64river_info\x18\x01 \x03(\x0b\x32\x0b.DriverInfo\"N\n\nDriverInfo\x12\x17\n\x0f\x61pi_description\x18\x01 \x02(\t\x12\x12\n\npublic_key\x18\x02 \x02(\x0c\x12\x13\n\x0b\x61\x33\x63_dd_uuid\x18\x03 \x02(\x0c')
)



_HEADER_MESSAGETYPE = _descriptor.EnumDescriptor(
  name='MessageType',
  full_name='Header.MessageType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='AuthTicket', index=0, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NonceExchange', index=1, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DriversInfo', index=2, number=3,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DeviceAccessRequest', index=3, number=4,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DeviceAccessResponse', index=4, number=5,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorMsg', index=5, number=6,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DriverAuthTicket', index=6, number=7,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=138,
  serialized_end=290,
)
_sym_db.RegisterEnumDescriptor(_HEADER_MESSAGETYPE)


_BLEMESSAGE = _descriptor.Descriptor(
  name='BLEmessage',
  full_name='BLEmessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='header', full_name='BLEmessage.header', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='payload', full_name='BLEmessage.payload', index=1,
      number=2, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=21,
  serialized_end=85,
)


_HEADER = _descriptor.Descriptor(
  name='Header',
  full_name='Header',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg_type', full_name='Header.msg_type', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=1,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _HEADER_MESSAGETYPE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=88,
  serialized_end=290,
)


_PAYLOAD = _descriptor.Descriptor(
  name='Payload',
  full_name='Payload',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='auth_ticket', full_name='Payload.auth_ticket', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_exc_msg', full_name='Payload.nonce_exc_msg', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='drivers_info_msg', full_name='Payload.drivers_info_msg', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='response', full_name='Payload.response', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='request', full_name='Payload.request', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='error_msg', full_name='Payload.error_msg', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=293,
  serialized_end=543,
)


_MESSAGEREQUEST = _descriptor.Descriptor(
  name='MessageRequest',
  full_name='MessageRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='target_uuid', full_name='MessageRequest.target_uuid', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='action', full_name='MessageRequest.action', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='delta', full_name='MessageRequest.delta', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=545,
  serialized_end=613,
)


_MESSAGERESPONSE = _descriptor.Descriptor(
  name='MessageResponse',
  full_name='MessageResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='target_uuid', full_name='MessageResponse.target_uuid', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='response', full_name='MessageResponse.response', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=615,
  serialized_end=671,
)


_AUTHENTICATIONTICKET = _descriptor.Descriptor(
  name='AuthenticationTicket',
  full_name='AuthenticationTicket',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='secret', full_name='AuthenticationTicket.secret', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pub', full_name='AuthenticationTicket.pub', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signature', full_name='AuthenticationTicket.signature', index=2,
      number=3, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='auth_nonce', full_name='AuthenticationTicket.auth_nonce', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=673,
  serialized_end=763,
)


_NONCEEXCHANGEMESSAGE = _descriptor.Descriptor(
  name='NonceExchangeMessage',
  full_name='NonceExchangeMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='enc_nonce', full_name='NonceExchangeMessage.enc_nonce', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='clear_nonce', full_name='NonceExchangeMessage.clear_nonce', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=765,
  serialized_end=827,
)


_ERRORMESSAGE = _descriptor.Descriptor(
  name='ErrorMessage',
  full_name='ErrorMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_code', full_name='ErrorMessage.error_code', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='error_description', full_name='ErrorMessage.error_description', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=829,
  serialized_end=890,
)


_DRIVERSINFOMESSAGE = _descriptor.Descriptor(
  name='DriversInfoMessage',
  full_name='DriversInfoMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='driver_info', full_name='DriversInfoMessage.driver_info', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=892,
  serialized_end=946,
)


_DRIVERINFO = _descriptor.Descriptor(
  name='DriverInfo',
  full_name='DriverInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='api_description', full_name='DriverInfo.api_description', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='DriverInfo.public_key', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='a3c_dd_uuid', full_name='DriverInfo.a3c_dd_uuid', index=2,
      number=3, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=948,
  serialized_end=1026,
)

_BLEMESSAGE.fields_by_name['header'].message_type = _HEADER
_BLEMESSAGE.fields_by_name['payload'].message_type = _PAYLOAD
_HEADER.fields_by_name['msg_type'].enum_type = _HEADER_MESSAGETYPE
_HEADER_MESSAGETYPE.containing_type = _HEADER
_PAYLOAD.fields_by_name['auth_ticket'].message_type = _AUTHENTICATIONTICKET
_PAYLOAD.fields_by_name['nonce_exc_msg'].message_type = _NONCEEXCHANGEMESSAGE
_PAYLOAD.fields_by_name['drivers_info_msg'].message_type = _DRIVERSINFOMESSAGE
_PAYLOAD.fields_by_name['response'].message_type = _MESSAGERESPONSE
_PAYLOAD.fields_by_name['request'].message_type = _MESSAGEREQUEST
_PAYLOAD.fields_by_name['error_msg'].message_type = _ERRORMESSAGE
_DRIVERSINFOMESSAGE.fields_by_name['driver_info'].message_type = _DRIVERINFO
DESCRIPTOR.message_types_by_name['BLEmessage'] = _BLEMESSAGE
DESCRIPTOR.message_types_by_name['Header'] = _HEADER
DESCRIPTOR.message_types_by_name['Payload'] = _PAYLOAD
DESCRIPTOR.message_types_by_name['MessageRequest'] = _MESSAGEREQUEST
DESCRIPTOR.message_types_by_name['MessageResponse'] = _MESSAGERESPONSE
DESCRIPTOR.message_types_by_name['AuthenticationTicket'] = _AUTHENTICATIONTICKET
DESCRIPTOR.message_types_by_name['NonceExchangeMessage'] = _NONCEEXCHANGEMESSAGE
DESCRIPTOR.message_types_by_name['ErrorMessage'] = _ERRORMESSAGE
DESCRIPTOR.message_types_by_name['DriversInfoMessage'] = _DRIVERSINFOMESSAGE
DESCRIPTOR.message_types_by_name['DriverInfo'] = _DRIVERINFO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

BLEmessage = _reflection.GeneratedProtocolMessageType('BLEmessage', (_message.Message,), dict(
  DESCRIPTOR = _BLEMESSAGE,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:BLEmessage)
  ))
_sym_db.RegisterMessage(BLEmessage)

Header = _reflection.GeneratedProtocolMessageType('Header', (_message.Message,), dict(
  DESCRIPTOR = _HEADER,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:Header)
  ))
_sym_db.RegisterMessage(Header)

Payload = _reflection.GeneratedProtocolMessageType('Payload', (_message.Message,), dict(
  DESCRIPTOR = _PAYLOAD,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:Payload)
  ))
_sym_db.RegisterMessage(Payload)

MessageRequest = _reflection.GeneratedProtocolMessageType('MessageRequest', (_message.Message,), dict(
  DESCRIPTOR = _MESSAGEREQUEST,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:MessageRequest)
  ))
_sym_db.RegisterMessage(MessageRequest)

MessageResponse = _reflection.GeneratedProtocolMessageType('MessageResponse', (_message.Message,), dict(
  DESCRIPTOR = _MESSAGERESPONSE,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:MessageResponse)
  ))
_sym_db.RegisterMessage(MessageResponse)

AuthenticationTicket = _reflection.GeneratedProtocolMessageType('AuthenticationTicket', (_message.Message,), dict(
  DESCRIPTOR = _AUTHENTICATIONTICKET,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:AuthenticationTicket)
  ))
_sym_db.RegisterMessage(AuthenticationTicket)

NonceExchangeMessage = _reflection.GeneratedProtocolMessageType('NonceExchangeMessage', (_message.Message,), dict(
  DESCRIPTOR = _NONCEEXCHANGEMESSAGE,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:NonceExchangeMessage)
  ))
_sym_db.RegisterMessage(NonceExchangeMessage)

ErrorMessage = _reflection.GeneratedProtocolMessageType('ErrorMessage', (_message.Message,), dict(
  DESCRIPTOR = _ERRORMESSAGE,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:ErrorMessage)
  ))
_sym_db.RegisterMessage(ErrorMessage)

DriversInfoMessage = _reflection.GeneratedProtocolMessageType('DriversInfoMessage', (_message.Message,), dict(
  DESCRIPTOR = _DRIVERSINFOMESSAGE,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:DriversInfoMessage)
  ))
_sym_db.RegisterMessage(DriversInfoMessage)

DriverInfo = _reflection.GeneratedProtocolMessageType('DriverInfo', (_message.Message,), dict(
  DESCRIPTOR = _DRIVERINFO,
  __module__ = 'ble_message_pb2'
  # @@protoc_insertion_point(class_scope:DriverInfo)
  ))
_sym_db.RegisterMessage(DriverInfo)


# @@protoc_insertion_point(module_scope)

#!bin/bash

echo "Protoc compiling..."

protoc -I proto_files --python_out=./ proto_files/ble_message.proto

# sudo python3 boot.py



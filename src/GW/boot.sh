#!bin/bash

echo "Gateway module is starting ..."

echo "Protoc compiling..."

protoc -I proto_files --python_out=./ proto_files/ble_message.proto

echo "[OK]"

# sudo python3 boot.py


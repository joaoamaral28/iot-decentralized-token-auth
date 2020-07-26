#include "src/ble_message.pb.h"
#include "pb_common.h"
#include "pb.h"
#include "pb_encode.h"

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

  // buffer to hold the serialized message
  uint8_t buffer[128];

  TestMessage message = TestMessage_init_zero;

  pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));

  message.test_number = 540;
  
  bool status = pb_encode(&stream, TestMessage_fields, &message);
  if (!status){
      Serial.println("Failed to encode");
      return;
  }

  Serial.print("Message Length: ");
  Serial.println(stream.bytes_written);

  Serial.print("Message: ");
  for(int i = 0; i<stream.bytes_written; i++){
    Serial.printf("%02X",buffer[i]);
  }

}

void serializeMessage(){

  // buffer to hold the serialized message
  uint8_t buffer[128];

  TestMessage message = TestMessage_init_zero;
  pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
  message.test_number = 540;
  
  bool status = pb_encode(&stream, TestMessage_fields, &message);
  if (!status){
      Serial.println("Failed to encode");
      return;
  }

  Serial.print("Message Length: ");
  Serial.println(stream.bytes_written);

  Serial.print("Message: ");
  for(int i = 0; i<stream.bytes_written; i++){
    Serial.printf("%02X",buffer[i]);
  }

}

void deserializeMessage(uint8_t buffer,size_t message_length){
  
  /* Allocate space for the decoded message. */
  BLEmessage message = BLEmessage_init_zero;
  
  /* Create a stream that reads from the buffer. */
  pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);
  
  /* Now we are ready to decode the message. */
  status = pb_decode(&stream, BLEmessage_fields, &message);
  
  /* Check for errors... */
  if (!status){
    Serial.printf("Decoding failed: %s\n", PB_GET_ERROR(&stream));
    return 1;
  }

  Serial.println(message);


  switch(message.header){
    case 1:
    case 2:
    case 3: 
  }

}

void loop() {
  // put your main code here, to run repeatedly:

}
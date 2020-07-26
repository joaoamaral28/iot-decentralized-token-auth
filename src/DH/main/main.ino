#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h> 
#include <sstream>

#include "FFat.h"
#include <esp_partition.h>

#include "LightDriver.h"
#include "TemperatureDriver.h"

#include "Cryptography.h"

#include "pb_common.h"
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "ble_message.pb.h"


/*
#define TEMP_SERVICE_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define TEMP_CHAR_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

#define LIGHT_SERVICE_UUID "874f41ac-b692-4d02-90fc-a41cfadf141f"
#define LIGHT_CHAR_UUID "9930cc28-648e-4769-a8ce-301823dd84dc"
*/
#define AUTHENTICATION_SERVICE_UUID "832fd58e-50c8-465b-ad1d-e6d6fccefe15"
#define AUTHENTICATION_CHAR_UUID "c4cbcdcd-ac39-4018-a27b-6a651fdcc797"
/*
#define COMMUNICATION_SERVICE_UUID "3e0462d0-8012-4cba-b0de-7c58e08a1eb8"
#define COMMUNICATION_CHAR_WX "e7b25571-0c11-49ff-90a7-2a07a754677d"
#define COMMUNICATION_CHAR_RX "718a3233-d55e-44e1-962b-5b2f287374c9"
*/

#define MAX_PAYLOAD_SIZE 514 // maximum size transported in each write/read operation
#define HEADER_SIZE 2 

// #define BLE_CHAR_AUTH_REQ 0x15

/* characteristic rx/tx state */
/*
typedef enum {
  BLE_CHAR_NO_INIT = 0x00, // state of the characteristic before being intialized in the service 
  BLE_CHAR_INIT = 0x10, // initial state of the characteristic after being initialized in the service 
  BLE_CHAR_AUTH_REQUIRED = 0x15, // characteristic indicates that its inherent service needs authentication 
  BLE_CHAR_STANDBY = 0x20, // characteristic is initialized successfully but has no value of interest to be read 
  BLE_CHAR_RX_READY = 0x24, // characteristic has been written and is awaiting reading request from the device central
  BLE_CHAR_RX_COMPLETE = 0x25, // characteristic has been successfully read by the device central
  BLE_CHAR_TX_READY = 0x28,  // characteristic is ready to be written to by the central
  BLE_CHAR_TX_COMPLETE = 0x29, // characteristic has been successfully written into by the central
} ble_char_state;
*

/* service state */

/*
typedef enum {
  BLE_SERVICE_NO_INIT = 0x00, // state of the service before being initialized in the ble server 
  BLE_SERVICE_INIT = 0x10, // state of the service after initialization 
  BLE_SERVICE_AUTH_REQUIRED = 0x30, // state indicating that authorization credentials are needed in order to access the service contents 
  BLE_SERVICE_AUTH_OK = 0x31, // state indicating that the authorization credentials were validated 
  BLE_SERVICE_AUTH_FAIL = 0x32, // state indicating that the received authorization credentials were invalid
} ble_service_state;
*/

typedef enum {
  DH_AUTH_REQ = 0X15, /* state indicating that the Device Host has initialized successfully and is currently waiting for an authentication ticket
                        from its soon to be master Gateway */
  DH_AUTH_NONCE_EXC_REQ = 0x20, /* state indicating that the received authentication ticket was validated and that the DH is now awaiting for a response 
                                    from is master gateway */
  DH_AUTH_OK = 0x30, /* state indicating the DH is properly authenticated with the master Gateway */
} dh_auth_state;

struct dh_gw_session {
  unsigned char session_key[32];
  unsigned char nonce1[16];
  unsigned char nonce2[16];
};

BLEDevice* device;
boolean deviceConnected = false; // flag indicating if device has received a connection

dh_gw_session session_data;
dh_gw_session client_session_data;

dh_auth_state authentication_state;


// installed driver setup
TemperatureDriver td;
LightDriver ld;

/* buffers storing cryptography keys */
unsigned char dhm_pub_key[452];
unsigned char dh_pub_key[452];
unsigned char dh_priv_key[1676];

size_t dhm_pub_key_len = 452;
size_t dh_pub_key_len = 452;
size_t dh_priv_key_len = 1676;

struct mydata_t { 
  size_t len; 
  uint8_t *buf; 
};

struct driver_info_t {
  mydata_t api_desc;
  mydata_t pub_key;
  mydata_t a3c_uuid;
};

std::string message_buffer;

std::vector<std::vector<uint8_t>> fragmentData(uint8_t* data, int buffer_size, int max_size){
    
    // calc number of fragments to split data buffer
    size_t frag_no =  ceil ((double) buffer_size/max_size);

    std::vector<std::vector<uint8_t>> fragments(frag_no);
    
    int i;
    for(i=0;i<frag_no-1;i++){ // for every fragment
        for(int j=0;j<max_size;j++){ // fill buffer
            fragments[i].push_back(data[max_size*i+j]);
        }
    }

    // fill last fragment separately
    for(int k=(i)*max_size;k<buffer_size;k++){
        fragments[i].push_back(data[k]);
    }

    return fragments;
}

boolean writeBytesCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) { 
    mydata_t **data = (mydata_t**) arg; 
    //Serial.println(field->tag);
    //Serial.println((**data).len);
    return pb_encode_tag_for_field(stream, field) && pb_encode_string(stream, (**data).buf, (**data).len); 
} 

boolean readBytesCallbackReq(pb_istream_t *stream, const pb_field_t *field, void **arg){
  
  size_t buffer_size;

  if(field->tag == MessageRequest_target_uuid_tag){
    Serial.println("Decoding target uuid field");
    buffer_size = 32;
  }else if(field->tag == MessageRequest_action_tag){
    Serial.println("Decoding driver action field");
    buffer_size = 32; 
  }else{
    Serial.println("[Error] Incorrect field->tag value");
    return false;
  }

  uint8_t buffer[buffer_size] = {0};
  //Serial.print("Bytes left:");
  //Serial.println(stream->bytes_left);
  if(stream->bytes_left > sizeof(buffer)) return false;
  if(!pb_read(stream,buffer,stream->bytes_left)) return false;
  std::vector<uint8_t> **p = (std::vector<uint8_t>**) arg;
  for(int i=0;i<sizeof(buffer);i++){
    //Serial.println(int(buffer[i]));
    (**p).push_back(buffer[i]);
  } 
  return true;
}

/* new callback to deal with nonce exchange decoding
could've adjusted the readBytesCallback to work with this one 
but that would imply passing the message type of the header
alongside the argument but im lazy */
boolean readBytesCallbackNE(pb_istream_t *stream, const pb_field_t *field, void **arg){
  
  size_t buffer_size;

  if(field->tag == NonceExchangeMessage_enc_nonce_tag){
    Serial.println("Decoding encrypted nonce");
    buffer_size = 32;
  }else{
    Serial.println("[Error] Incorrect field->tag value");
    return false;
  }

  uint8_t buffer[buffer_size] = {0};

  //Serial.print("Bytes left:");
  //Serial.println(stream->bytes_left);
    
  if(stream->bytes_left > sizeof(buffer)) return false;
  if(!pb_read(stream,buffer,stream->bytes_left)) return false;

  std::vector<uint8_t> **p = (std::vector<uint8_t>**) arg;

  for(int i=0;i<sizeof(buffer);i++){
    //Serial.println(int(buffer[i]));
    (**p).push_back(buffer[i]);
  } 
  
  return true;
}

boolean readBytesCallback(pb_istream_t *stream, const pb_field_t *field, void **arg){

  size_t buffer_size;

  if(field->tag == AuthenticationTicket_auth_nonce_tag ){
    Serial.println("Decoding authentication nonce");
    buffer_size = 16;
  }else if(field->tag == AuthenticationTicket_signature_tag ){
    Serial.println("Decoding signature");
    buffer_size = 256;
  }else if(field->tag == AuthenticationTicket_pub_tag ){
    Serial.println("Decoding public ticket section");
    buffer_size = stream->bytes_left;
  }else if(field->tag == AuthenticationTicket_secret_tag ){
    Serial.println("Decoding private ticket section");
    buffer_size = 256; 
  }else if(field->tag == NonceExchangeMessage_enc_nonce_tag){
    Serial.println("Decoding encrypted nonce");
    buffer_size = 16;
  }else{
    Serial.println("[Error] Incorrect field->tag value");
    return false;
  }

  uint8_t buffer[buffer_size] = {0};
    
  if(stream->bytes_left > sizeof(buffer)) return false;
  if(!pb_read(stream,buffer,stream->bytes_left)) return false;

  std::vector<uint8_t> **p = (std::vector<uint8_t>**) arg;

  for(int i=0;i<sizeof(buffer);i++){
    //Serial.println(int(buffer[i]));
    (**p).push_back(buffer[i]);
  } 
  
  //uint8_t **ptr1 = (uint8_t**) arg;
  //**ptr1 = {1,2,3};
  /*
  int **ptr1;
  ptr1 = (int**) arg;
  //int b = **ptr1;
  **ptr1 = 2;
  //Serial.println(b);
  */

  return true;
 
}

class ServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      Serial.println("New connection received!");
      deviceConnected = true;
    };

    void onDisconnect(BLEServer* pServer) {
      Serial.println("Disconnected!");
      deviceConnected = false;              
      //pCharacteristic->setBroadcastProperty(false); // advertise back the service in case a unexpected disconection occurrs 
      // < TODO >
    }
};

class CharacteristicCallbacks: public BLECharacteristicCallbacks{
    void onRead(BLECharacteristic* pCharacteristic){
      //BLEUUID uuid = pCharacteristic->getUUID();
      //std::string s_uuid = uuid.toString();
      //Serial.print("Characteristic ");
      //Serial.write("%s",s_uuid);
      //Serial.println(" was read by central");
      //Serial.println("Characteristic was read by central");
    }
    void onWrite(BLECharacteristic* pCharacteristic){
      //Serial.println("Characteristic was written by central");
      std::string value = pCharacteristic->getValue();

      unsigned char sequence_no = value.at(0);
      unsigned char end_flag = value.at(1);
      
      std::string payload = value.substr(2, value.length()-1);

      Serial.print("Sequence number: ");
      Serial.print(sequence_no);
      Serial.print(" End flag: ");
      Serial.println(end_flag);

      Serial.println(value.length());
  
      // if value is smaller than the maximum allowed then the message is most likely singular 
      // or corresponds to the last message of a certain message sequence 
      // either way the sequence_no and end_flag help dictate these ocurrences apart
      if(value.length()<MAX_PAYLOAD_SIZE){ 
        if(end_flag == 1){
          if(sequence_no == 0){ // standalone message
            Serial.println("Standalone message received!");

            // Allocate space for the decoded message. 
            BLEmessage message = BLEmessage_init_zero;

            uint8_t buf[payload.length()];
            for(int i=0;i<payload.length();i++){
              buf[i] = payload[i];
            }
            size_t msg_len = sizeof(buf)/sizeof(buf[0]);

            if(payload[3] == Header_MessageType_NonceExchange){
              Serial.println("Nonce exchange response message received");
              if(authentication_state = DH_AUTH_NONCE_EXC_REQ){ // in case the device is expecting a response from the GW
                // parse and decode data
                pb_istream_t stream = pb_istream_from_buffer(buf, msg_len);

                std::vector<unsigned char> enc_nonce_buf;
   
                message.payload.nonce_exc_msg.enc_nonce.funcs.decode = readBytesCallbackNE;
                message.payload.nonce_exc_msg.enc_nonce.arg = (void **)&enc_nonce_buf;
 
                if (!pb_decode(&stream, BLEmessage_fields, &message)){
                  Serial.printf("[Error] Decoding failed: %s\n", PB_GET_ERROR(&stream));
                  return;
                }
                Serial.println("[OK] Message decoding");
    
                unsigned char* p_enc_nonce = &enc_nonce_buf[16];
                unsigned char* p_enc_nonce_iv = &enc_nonce_buf[0];
                
                //Correct!
                //for(int i=0;i<16;i++) Serial.println(int(p_enc_nonce_iv[i]));
                  
                // decrypt nonce
                unsigned char dec_nonce[16];
                if(!decryptAES(p_enc_nonce,dec_nonce,p_enc_nonce_iv, session_data.session_key, 16)){
                  return;
                }
  
                // check if it matches sent nonce2 
                if(memcmp(dec_nonce, session_data.nonce2, sizeof(dec_nonce))!=0){
                  Serial.println("[Error] Decrypted nonce value does not match nonce sent previously!");
                  return;
                }

                Serial.println("[OK] Decrypted nonce matches previously sent nonce!");

                // update internal state
                authentication_state = DH_AUTH_OK;

                // session setup is now complete
                Serial.println("[OK] Session established successfully with target GW");
              
                // DH will now inform the authenticated gateway of the DDs it contain 
                // along with the DDs public Key (K+dd), API and the UUID of their A3C server
                uint8_t* ld_api_desc = ld.getDriverDescription();
                uint8_t* ld_pub_key = (unsigned char*) ld.public_key;
                uint8_t* ld_a3c_uuid = (unsigned char*) ld.uuid_a3c_dd.c_str();
                
                uint8_t* td_api_desc = td.getDriverDescription();
                uint8_t* td_pub_key = (unsigned char*) td.public_key;
                uint8_t* td_a3c_uuid = (unsigned char*) td.uuid_a3c_dd.c_str();

                // declaration of buffers to be passed into the encode callback    
                driver_info_t driver_info_buf1;
                driver_info_t driver_info_buf2;
              
                driver_info_buf1.api_desc.buf = ld_api_desc;
                driver_info_buf1.api_desc.len = ld.getDescLen();
               
                driver_info_buf1.pub_key.buf = ld_pub_key;
                driver_info_buf1.pub_key.len = ld.getPubKeyLen();
              
                driver_info_buf1.a3c_uuid.buf =ld_a3c_uuid;
                driver_info_buf1.a3c_uuid.len = 32;
              
                driver_info_buf2.api_desc.buf = td_api_desc;
                driver_info_buf2.api_desc.len = td.getDescLen();
                
                driver_info_buf2.pub_key.buf = td_pub_key;
                driver_info_buf2.pub_key.len = td.getPubKeyLen();
              
                driver_info_buf2.a3c_uuid.buf = td_a3c_uuid;
                driver_info_buf2.a3c_uuid.len = 32;

                // Init driver1
                DriverInfo driver_info = DriverInfo_init_zero;
                driver_info.api_description.funcs.encode = &writeBytesCallback;
                driver_info.api_description.arg =  (void**) &driver_info_buf1.api_desc;
                driver_info.public_key.funcs.encode = &writeBytesCallback;
                driver_info.public_key.arg =  (void**) &driver_info_buf1.pub_key;
                driver_info.a3c_dd_uuid.funcs.encode = &writeBytesCallback;
                driver_info.a3c_dd_uuid.arg =  (void**) &driver_info_buf1.a3c_uuid;
              
                // Init driver2
                DriverInfo driver_info2 = DriverInfo_init_zero;
                driver_info2.api_description.funcs.encode = &writeBytesCallback;
                driver_info2.api_description.arg =  (void**) &driver_info_buf2.api_desc;
                driver_info2.public_key.funcs.encode = &writeBytesCallback;
                driver_info2.public_key.arg =  (void**) &driver_info_buf2.pub_key;
                driver_info2.a3c_dd_uuid.funcs.encode = &writeBytesCallback;
                driver_info2.a3c_dd_uuid.arg =  (void**) &driver_info_buf2.a3c_uuid;

                // encode message
                BLEmessage driver_info_msg = BLEmessage_init_zero;
                
                driver_info_msg.header.msg_type = Header_MessageType_DriversInfo;
                driver_info_msg.payload.has_drivers_info_msg = true;
                
                driver_info_msg.payload.drivers_info_msg.driver_info_count = 2;
                
                driver_info_msg.payload.drivers_info_msg.driver_info[0] = driver_info;
                driver_info_msg.payload.drivers_info_msg.driver_info[1] = driver_info2;
                
                size_t msg_len = driver_info_buf1.api_desc.len + driver_info_buf1.pub_key.len + driver_info_buf1.a3c_uuid.len 
                + driver_info_buf2.api_desc.len + driver_info_buf2.pub_key.len + driver_info_buf2.a3c_uuid.len + 30; // X+13
                uint8_t encoded_msg[msg_len] = {0};

                Serial.print("Message len: ");
                Serial.println(msg_len);
                
                pb_ostream_t msg_stream = pb_ostream_from_buffer(encoded_msg, msg_len);
                
                if(!pb_encode(&msg_stream, BLEmessage_fields, &driver_info_msg)){
                  Serial.printf("[Error] Encoding failed: %s\n", PB_GET_ERROR(&msg_stream));
                  //pCharacteristic->setValue("Internal error");
                  //pCharacteristic->notify();
                  return;
                }
                Serial.println("[OK] Message encoding");
                //Serial.println(msg_stream.bytes_written);
                
                //Serial.print("Message: ");
                //for(int i = 0; i<msg_stream.bytes_written; i++){
                //  Serial.printf("%02X",encoded_msg[i]);
                //}

                // fragment serialized message to fit max MTU constraint
                if(msg_len>(MAX_PAYLOAD_SIZE-HEADER_SIZE)){
                  Serial.println("\nMessage exceeds maximum link size (514). Fragmenting data...");
                  std::vector<std::vector<uint8_t>> fragments = fragmentData(encoded_msg,msg_len,(MAX_PAYLOAD_SIZE-HEADER_SIZE));
                  Serial.printf("Message data split into %d fragments\n",fragments.size());
                  // notify gateway
                  std::string last_msg = "0";  
                  for(int i=0;i<fragments.size();i++){      
                    if(i==fragments.size()-1) // last message
                      last_msg = "1";      
                    std::string s_r(&fragments[i][0], &fragments[i][0] + fragments[i].size());
                    std::ostringstream s;
                    s << i;
                    Serial.printf("Notifying message fragment %d...\n",i);
                    
                    Serial.println(s.str().c_str());
                    Serial.println(last_msg.c_str());
                    
                    pCharacteristic->setValue( s.str() + last_msg + s_r);
                    pCharacteristic->notify();  
                    delay(100); // 100 ms delay between notifications                 
                  }                  
                }else{
                  std::string s_r(encoded_msg, encoded_msg + msg_len);
                  pCharacteristic->setValue("01" + s_r);
                  pCharacteristic->notify();             
                }
                
                return ;

              }else{
                Serial.println("Unexpected nonce exchange message received. Discarting message...");
                return;
              }
            }else if(payload[3] == Header_MessageType_DeviceAccessRequest){
                
                // parse and decode data
                pb_istream_t stream = pb_istream_from_buffer(buf, msg_len);

                std::vector<unsigned char> target_dd, dd_action;
   
                message.payload.request.target_uuid.funcs.decode = readBytesCallbackReq;
                message.payload.request.target_uuid.arg = (void **)&target_dd;

                message.payload.request.action.funcs.decode = readBytesCallbackReq;
                message.payload.request.action.arg = (void **)&dd_action;
 
                if (!pb_decode(&stream, BLEmessage_fields, &message)){
                  Serial.printf("[Error] Decoding failed: %s\n", PB_GET_ERROR(&stream));
                  return;
                }
                Serial.println("[OK] Message decoding");
          
                std::string str_target_dd(target_dd.begin(), target_dd.end());
                std::string str_dd_action(dd_action.begin(), dd_action.end());

                BLEmessage response = BLEmessage_init_zero;

                mydata_t target_uuid_buf, response_buf;
                
                target_uuid_buf.len = 32;
                target_uuid_buf.buf = &target_dd[0];
                                
                if(str_target_dd == ld.uuid_dd){
                  Serial.printf("[OK] Client target driver is light driver, uuid %s\n",ld.uuid_dd.c_str());
                }else if(str_target_dd == td.uuid_dd){
                  Serial.printf("[OK] Client target driver is temperature driver, uuid %s\n",td.uuid_dd.c_str());
                  /*if(str_dd_action.compare("readValue") == 0){
                    Serial.println("Action: readValue");
                    uint8_t *tmp_val;
                    tmp_val = (uint8_t*) td.readValue();
                    response_buf.len = sizeof(tmp_val)/sizeof(tmp_val[0]);
                    response_buf.buf = tmp_val;
                    //std::string s_val((char*)tmp_val);
                    //Serial.print("Result: ");
                    //Serial.println(s_val.c_str());
                  }else if(str_dd_action == "calibrateSensor"){
                    
                  }else{
                    Serial.println("Invalid action received");
                  }
                  */
                }else{
                  Serial.println("[Error] Invalid target driver");
                  return;
                }

                  uint8_t tmp_val = td.readValue();
                  
                  response_buf.len = 1;
                  response_buf.buf = &tmp_val;
                //std::string s_val((char*)tmp_val);    

                response.header.msg_type = Header_MessageType_DeviceAccessResponse;

                response.payload.has_response = true;
                
                response.payload.response.target_uuid.funcs.encode = &writeBytesCallback;
                response.payload.response.target_uuid.arg = (void**) &target_uuid_buf;

                response.payload.response.response.funcs.encode = &writeBytesCallback;
                response.payload.response.response.arg = (void**) &response_buf;

                size_t response_len = target_uuid_buf.len + response_buf.len + 13; // 32+16+X
                uint8_t encoded_response[response_len] = {0};
            
                pb_ostream_t response_stream = pb_ostream_from_buffer(encoded_response, response_len);
            
                if(!pb_encode(&response_stream, BLEmessage_fields, &response)){
                  Serial.printf("[Error] Encoding failed: %s\n", PB_GET_ERROR(&response_stream));
                  //pCharacteristic->setValue("Internal error");
                  //pCharacteristic->notify();
                  return;
                }
                
                //Serial.println("[OK] Message encoding");
                Serial.println(response_stream.bytes_written);
                
                std::string s_r(encoded_response, encoded_response + response_len);

                if(message.payload.request.has_delta){
                   Serial.print("Received request has delta value specification: ");
                   Serial.println(message.payload.request.delta);
                   delay(800);
                }
                
                pCharacteristic->setValue("01"+s_r);
                pCharacteristic->notify();
              
                return;


            }
          }else{ // last message from a message stream 
            Serial.println("Last sequence message received!");
            message_buffer = message_buffer + payload; // update message buffer with the last section of the message

            // deserialize message using protocol buffer decoder

            // Allocate space for the decoded message. 
            BLEmessage message = BLEmessage_init_zero;

            uint8_t buf[message_buffer.length()];
            for(int i=0;i<message_buffer.length();i++){
              buf[i] = message_buffer[i];
            }

            message_buffer = "";

            size_t msg_len = sizeof(buf)/sizeof(buf[0]);

            // The third byte of the buffer corresponds to the message_type header field
            // As such, the verification of the type of received message is done here instead 
            // of using the field message.header.msg_type since we need to know
            // the type of message first in order to apply the respective callbacks.
            // Otherwise we would need to decode 2 times: one for retrieving the 
            // header type value and a second time to apply the proper callbacks
            // to the fields the payload contains
            
            if(message_buffer[3]==Header_MessageType_AuthTicket){ 
              
              Serial.println("Authentication ticket received");

              pb_istream_t stream = pb_istream_from_buffer(buf, msg_len);
              std::vector<unsigned char> secret_buf, pub_buf, sign_buf, nonce_buf;
  
              message.payload.auth_ticket.secret.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.secret.arg = (void **)&secret_buf;
  
              message.payload.auth_ticket.signature.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.signature.arg = (void **)&sign_buf;
             
              message.payload.auth_ticket.pub.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.pub.arg =  (void **)&pub_buf;
              
              message.payload.auth_ticket.auth_nonce.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.auth_nonce.arg = (void **)&nonce_buf;
                
              // Now we are ready to decode the message.
              boolean status = pb_decode(&stream, BLEmessage_fields, &message);
                      
              // Check for errors...
              if (!status){
                Serial.printf("[Error] Decoding failed: %s\n", PB_GET_ERROR(&stream));
                return;
              }
              Serial.println("[OK] Message decoding");
  
              unsigned char* p_secret = &secret_buf[0];
              //unsigned char* p_pub = &pub_buf[0];
              std::string pub(pub_buf.begin(), pub_buf.end());
              unsigned char* p_sign = &sign_buf[0];
              unsigned char* p_nonce = &nonce_buf[0];
              
              //for(int i=0;i<nonce_buf.size();i++) Serial.println(int(p_nonce[i]));
              
              if(!validateAuthenticationTicket(p_secret, (size_t) secret_buf.size() ,pub, p_sign, (size_t) sign_buf.size(), p_nonce, dhm_pub_key, dh_priv_key, dhm_pub_key_len,dh_priv_key_len )){
                Serial.println("[ERROR] Received authentication token is invalid!");
                Serial.println("Session setup failed!");
                //pCharacteristic->setValue("0x32"); // failed authentication code
                //pCharacteristic->notify();
                return;
              }
              
              Serial.println("[OK] Authentication token is valid!");

              // Decrypt secret part of the ticket that contains the symmetric session key
              unsigned char ticket_key[16];

              unsigned char p[256];
              for(int i=0;i<256;i++){
                p[i] = p_secret[i];
              }
              
              size_t dec_len = decryptRSA(p,ticket_key, dh_priv_key, secret_buf.size(), dh_priv_key_len, sizeof(ticket_key)/sizeof(ticket_key[0]));
              if(!dec_len){
                //pCharacteristic->setValue("x040"); // failed decryption code
                //pCharacteristic->notify();
                return;
              }

              //for(int i=0;i< sizeof(p)/sizeof(p[0]);i++) Serial.println(int(p[i]));
              //Serial.println("Ticket key RSA decrypt");
              //for(int i=0;i< sizeof(ticket_key)/sizeof(ticket_key[0]);i++) Serial.println(int(ticket_key[i]));

              // generate nonce2 (n2)
              unsigned char nonce2[16];
              mbedtls_ctr_drbg_context ctr_drbg;
              mbedtls_ctr_drbg_init( &ctr_drbg );
              int ret = 0;
              if((ret=mbedtls_ctr_drbg_random(&ctr_drbg,nonce2,sizeof(nonce2)/sizeof(nonce2[0])))!=0){
                Serial.println("[Error] Failed to generate random nonce2");
                return;
              }

              //for(int i=0;i<16;i++) Serial.println(nonce2[i]);
              
              // compute derived session key K' = digest(n1,n2,K)
              unsigned char derived_key[32];
              unsigned char nonce1[16];
              
              ret=0;
              if((ret=generateSessionKey(p_nonce, nonce2, ticket_key, derived_key, nonce_buf.size(), sizeof(nonce2)/sizeof(nonce2[0]), sizeof(ticket_key)/sizeof(ticket_key[0]), 32))!=0){
                return;
              }

             //for(int i=0;i<32;i++) Serial.println(derived_key[i]);

              // encrypt nonce1
              // < TODO >
              unsigned char enc_nonce1[16]; // encrypted output
              unsigned char iv[16]; // buffer to store cipher IV
              ret=0;
              if((ret=encryptAES(p_nonce, enc_nonce1, iv, derived_key, nonce_buf.size()))!=0){
                return;
              }
              
              //Serial.println("INIT VECTOR");
              //for(int i=0;i<sizeof(iv)/sizeof(iv[0]);i++) Serial.println(iv[i]);
              //Serial.println("Decrypted nonce1");
              //for(int i=0;i<nonce_buf.size();i++) Serial.println(p_nonce[i]);
              //Serial.println("Encrypted nonce1");
              //for(int i=0;i<sizeof(enc_nonce1)/sizeof(enc_nonce1[0]);i++) Serial.println(enc_nonce1[i]);

              BLEmessage response = BLEmessage_init_zero;
              mydata_t enc_nonce1_buf, nonce2_buf;

              size_t enc_n1_iv_len = sizeof(iv)/sizeof(iv[0]) + sizeof(enc_nonce1)/sizeof(enc_nonce1[0]);
              unsigned char enc_n1_iv[enc_n1_iv_len] = {0};
              
              for(int i=0;i<16;i++) enc_n1_iv[i] = iv[i];
              for(int i=0;i<enc_n1_iv_len;i++) enc_n1_iv[i+16] = enc_nonce1[i];
              
              //memcpy(enc_n1_iv, iv, 16 * sizeof(unsigned char));
              //memcpy(enc_n1_iv, enc_nonce1, 128 * sizeof(unsigned char));

              //enc_nonce1_buf.len = 128;
              //enc_nonce1_buf.buf = enc_nonce1;
              enc_nonce1_buf.len = enc_n1_iv_len;
              enc_nonce1_buf.buf = enc_n1_iv;

              //Serial.println("TOTAL BUFFER");
              //for(int i=0;i<enc_n1_iv_len;i++) Serial.println(int(enc_n1_iv[i]));

              nonce2_buf.len = sizeof(nonce2)/sizeof(nonce2[0]);
              nonce2_buf.buf = nonce2;

              response.header.msg_type = Header_MessageType_NonceExchange;

              response.payload.has_nonce_exc_msg = true;

              response.payload.nonce_exc_msg.enc_nonce.funcs.encode = &writeBytesCallback;
              response.payload.nonce_exc_msg.enc_nonce.arg = (void**) &enc_nonce1_buf;

              response.payload.nonce_exc_msg.clear_nonce.funcs.encode = &writeBytesCallback;
              response.payload.nonce_exc_msg.clear_nonce.arg = (void**) &nonce2_buf;

              size_t response_len = enc_nonce1_buf.len + nonce2_buf.len + 13; // 32+16+X
              uint8_t encoded_response[response_len] = {0};
              
              pb_ostream_t response_stream = pb_ostream_from_buffer(encoded_response, response_len);
              
              if(!pb_encode(&response_stream, BLEmessage_fields, &response)){
                Serial.printf("[Error] Encoding failed: %s\n", PB_GET_ERROR(&response_stream));
                //pCharacteristic->setValue("Internal error");
                //pCharacteristic->notify();
                return;
              }
              Serial.println("[OK] Message encoding");
              Serial.println(response_stream.bytes_written);

              std::string s_r(encoded_response, encoded_response + response_len);
         
              // send response: < n2, {n1}K' > back to master GW 
              //pCharacteristic->setBroadcastProperty(false); // authentication is successfull so we can stop advertising the authentication characteristic
              //pCharacteristic->setValue("01" + s_response); // 0 -> single frame / 1-> ending frame / authentication ok code
              pCharacteristic->setValue("01" + s_r);
              pCharacteristic->notify();

              // update connection data
              std::copy(derived_key, derived_key + 32, session_data.session_key);
              std::copy(p_nonce, p_nonce + 16, session_data.nonce1);
              std::copy(nonce2, nonce2 +16, session_data.nonce2);

              // update internal state
              authentication_state = DH_AUTH_NONCE_EXC_REQ;

              // empty the buffer
              message_buffer.empty();

              /** <TODO> BLE Extras ***/
              //BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT_MITM);
              //BLEDevice::setSecurityCallbacks = onConfirmPIN(1234);
              //BLEDevice::whiteListAdd(BLEAddress);
              //BLEDevice::whiteListRemove(BLEAddress);
              
            }else if(message_buffer[3] == Header_MessageType_NonceExchange){
              Serial.println("Nonce exchange response message received");
              /* Note: The nonce exchange response from the gateway is a small message and wont be handled inside this outer if condition
                 (that is, multiple segmented messages).  */
              
              if(authentication_state = DH_AUTH_NONCE_EXC_REQ){ // in case the device is expecting a response from the GW
                // parse data                
                // decrypt nonce
                // check if it matches sent nonce2 
                // conclude session setup with master GW
              }else{
                Serial.println("Unexpected nonce exchange message received. Discarting message...");
                return;
              }
              
            }else if(message_buffer[3] == Header_MessageType_DriverAuthTicket){
              Serial.println("Driver authentication ticket received!");

              pb_istream_t stream = pb_istream_from_buffer(buf, msg_len);
              std::vector<unsigned char> secret_buf, pub_buf, sign_buf, nonce_buf;
  
              message.payload.auth_ticket.secret.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.secret.arg = (void **)&secret_buf;
  
              message.payload.auth_ticket.signature.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.signature.arg = (void **)&sign_buf;
             
              message.payload.auth_ticket.pub.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.pub.arg =  (void **)&pub_buf;
              
              message.payload.auth_ticket.auth_nonce.funcs.decode = &readBytesCallback;
              message.payload.auth_ticket.auth_nonce.arg = (void **)&nonce_buf;
                
              // Now we are ready to decode the message.
              boolean status = pb_decode(&stream, BLEmessage_fields, &message);
                      
              // Check for errors...
              if (!status){
                Serial.printf("[Error] Decoding failed: %s\n", PB_GET_ERROR(&stream));
                return;
              }
              Serial.println("[OK] Message decoding");

              unsigned char* p_secret = &secret_buf[0];
              //unsigned char* p_pub = &pub_buf[0];
              std::string encoded_pub(pub_buf.begin(), pub_buf.end());
              unsigned char* p_sign = &sign_buf[0];
              unsigned char* p_nonce = &nonce_buf[0];

              std::vector<unsigned char> decoded_pub = base64_decode(encoded_pub);              
              std::string pub(decoded_pub.begin(), decoded_pub.end());
    
              //Serial.write(pub.c_str());
              //Serial.println();

              pub.erase(std::remove_if(pub.begin(), pub.end(), &filterChar), pub.end()); 

              //Serial.write(pub.c_str());
              //Serial.println();

              std::istringstream iss(pub);
              std::string t;
              std::map<std::string,std::string> pub_dict;
            
              while(std::getline(iss,t,',')){     
                  size_t pos = t.find(':');
                  std::string key = t.substr(0,pos);
                  std::string value = t.substr(pos+1);
                  pub_dict.insert(std::make_pair(key, value));
              }

              //Serial.println("Public part parsed OK");

              unsigned char* a3c_dd_pub_key;
              unsigned char* dd_pub_key;
              unsigned char* dd_priv_key;
              size_t a3c_dd_key_len, dd_pub_key_len, dd_priv_key_len;
              if(pub_dict.at("dd_id") == ld.uuid_dd){
                Serial.printf("[OK] Client target driver is light driver, uuid %s\n",ld.uuid_dd.c_str());
                a3c_dd_pub_key = (unsigned char*)ld.a3c_dd_public_key;
                dd_pub_key = (unsigned char*)ld.public_key;
                dd_priv_key = (unsigned char*)ld.private_key;
                a3c_dd_key_len = ld.getA3CKeyLen() + 1;
                dd_pub_key_len = ld.getPubKeyLen() + 1;
                dd_priv_key_len = ld.getPrivKeyLen() + 1;                
              }else if (pub_dict.at("dd_id") == td.uuid_dd){
                Serial.printf("[OK] Client target driver is temperature driver, uuid %s\n", td.uuid_dd.c_str());
                a3c_dd_pub_key = (unsigned char*)td.a3c_dd_public_key;
                dd_pub_key = (unsigned char*)td.public_key;
                dd_priv_key = (unsigned char*)td.private_key;
                a3c_dd_key_len = td.getA3CKeyLen() + 1;
                dd_pub_key_len = td.getPubKeyLen() + 1;
                dd_priv_key_len = td.getPrivKeyLen() + 1;             
              }else{
                Serial.println("[Error] Invalid target driver");
                return;
              }
              
              if(!validateAuthenticationTicket(p_secret, (size_t) secret_buf.size() ,encoded_pub, p_sign, (size_t) sign_buf.size(), p_nonce,
              a3c_dd_pub_key, dd_priv_key, a3c_dd_key_len,dd_priv_key_len)){              
                Serial.println("[ERROR] Received authentication token is invalid!");
                Serial.println("Session setup failed!");
                //pCharacteristic->setValue("0x32"); // failed authentication code
                //pCharacteristic->notify();
                return;             
              }

              Serial.println("[OK] Authentication token is valid!");
              
              // Decrypt secret part of the ticket that contains the symmetric session key
              unsigned char ticket_key[16];

              unsigned char p[256];
              for(int i=0;i<256;i++){
                p[i] = p_secret[i];
              }
              
              size_t dec_len = decryptRSA(p,ticket_key, dd_priv_key, secret_buf.size(), dd_priv_key_len, sizeof(ticket_key)/sizeof(ticket_key[0]));
              if(!dec_len){
                Serial.println("[Error] Decryption failed!");
                //pCharacteristic->setValue("x040"); // failed decryption code
                //pCharacteristic->notify();
                return;
              }

              Serial.println("[OK] Secret key decryption");
              
              // generate nonce2 (n2)
              unsigned char nonce2[16];
              mbedtls_ctr_drbg_context ctr_drbg;
              mbedtls_ctr_drbg_init( &ctr_drbg );
              int ret = 0;
              if((ret=mbedtls_ctr_drbg_random(&ctr_drbg,nonce2,sizeof(nonce2)/sizeof(nonce2[0])))!=0){
                Serial.println("[Error] Failed to generate random nonce2");
                return;
              }

              //for(int i=0;i<16;i++) Serial.println(nonce2[i]);
              
              // compute derived session key K' = digest(n1,n2,K)
              unsigned char derived_key[32];
              unsigned char nonce1[16];
              
              ret=0;
              if((ret=generateSessionKey(p_nonce, nonce2, ticket_key, derived_key, nonce_buf.size(), sizeof(nonce2)/sizeof(nonce2[0]), sizeof(ticket_key)/sizeof(ticket_key[0]), 32))!=0){
                return;
              }

             //for(int i=0;i<32;i++) Serial.println(derived_key[i]);

              // encrypt nonce1
              unsigned char enc_nonce1[16]; // encrypted output
              unsigned char iv[16]; // buffer to store cipher IV
              ret=0;
              if((ret=encryptAES(p_nonce, enc_nonce1, iv, derived_key, nonce_buf.size()))!=0){
                return;
              }

              
              BLEmessage response = BLEmessage_init_zero;
              mydata_t enc_nonce1_buf, nonce2_buf;

              size_t enc_n1_iv_len = sizeof(iv)/sizeof(iv[0]) + sizeof(enc_nonce1)/sizeof(enc_nonce1[0]);
              unsigned char enc_n1_iv[enc_n1_iv_len] = {0};
              
              for(int i=0;i<16;i++) enc_n1_iv[i] = iv[i];
              for(int i=0;i<enc_n1_iv_len;i++) enc_n1_iv[i+16] = enc_nonce1[i];
              
              enc_nonce1_buf.len = enc_n1_iv_len;
              enc_nonce1_buf.buf = enc_n1_iv;

              //Serial.println("TOTAL BUFFER");
              //for(int i=0;i<enc_n1_iv_len;i++) Serial.println(int(enc_n1_iv[i]));

              nonce2_buf.len = sizeof(nonce2)/sizeof(nonce2[0]);
              nonce2_buf.buf = nonce2;

              response.header.msg_type = Header_MessageType_NonceExchange;

              response.payload.has_nonce_exc_msg = true;

              response.payload.nonce_exc_msg.enc_nonce.funcs.encode = &writeBytesCallback;
              response.payload.nonce_exc_msg.enc_nonce.arg = (void**) &enc_nonce1_buf;

              response.payload.nonce_exc_msg.clear_nonce.funcs.encode = &writeBytesCallback;
              response.payload.nonce_exc_msg.clear_nonce.arg = (void**) &nonce2_buf;

              size_t response_len = enc_nonce1_buf.len + nonce2_buf.len + 13; // 32+16+X
              uint8_t encoded_response[response_len] = {0};
              
              pb_ostream_t response_stream = pb_ostream_from_buffer(encoded_response, response_len);
              
              if(!pb_encode(&response_stream, BLEmessage_fields, &response)){
                Serial.printf("[Error] Encoding failed: %s\n", PB_GET_ERROR(&response_stream));
                //pCharacteristic->setValue("Internal error");
                //pCharacteristic->notify();
                return;
              }
              Serial.println("[OK] Message encoding");
              //Serial.println(response_stream.bytes_written);
              
              std::string s_r(encoded_response, encoded_response + response_len);
              //char seq_no = '0';
              //char end_flag = '1';

              // send response: < n2, {n1}K' > back to client (through the GW)
              pCharacteristic->setValue("01"+s_r);
              pCharacteristic->notify();

             //delete s_r;

              /* update client<->dd session data */
              /*
              std::copy(derived_key, derived_key + 32, session_data.session_key);
              std::copy(p_nonce, p_nonce + 16, session_data.nonce1);
              std::copy(nonce2, nonce2 +16, session_data.nonce2);
              */
              
            }else if(message_buffer[3] == Header_MessageType_DeviceAccessRequest){
              Serial.println("Access request received");
            }else{
              Serial.println("[ERROR] Unknown message type header");
            }

            // create communication channel with the authenticated gateway 
            
            // create specific service and characteristic for the specific gateway 

            // Apply security to that service/characteristic 

            // notify the master gateway that authentication was sucessful and inform of such service 

            // reset
            //message_buffer_flag = "FREE";
            //msg_cnt = 0;
  
            //message_buffer = "";

            return;
          }
        }
      }else{
        Serial.print("Message received ");
        Serial.println(sequence_no); 
        
        // otherwise there are multiple messages to be processed
        //message_buffer_flag = header;
        message_buffer = message_buffer + payload;
        //msg_cnt++;
        //Serial.print("Message nº");
        //Serial.println(msg_cnt);
      }
    }
};

void setup() {
  Serial.begin(115200);

  /* initialize partition */
  if(!FFat.begin(true)){
    Serial.println("Partition mount failed");
    return;
  }
  Serial.println("File system mounted successfully");

  Serial.printf("Total space: %10lu\n", FFat.totalBytes());
  Serial.printf("Free space: %10lu\n", FFat.freeBytes());


  /* Load keys from local partition */
  Serial.println("Reading keys from device local partition");
  int idx = 0;
  
  /* DH public key */
  File f_public = FFat.open("/public.pem");
  if(!f_public){
    Serial.println("Failed opening DH public key file!");
    f_public.close();
    return;
  }

  while(f_public.available()){
    dh_pub_key[idx] = f_public.read();
    //Serial.write(f_public.read());
    idx++;
  }
  idx = 0;

  //for(int i=0;i<sizeof(dh_pub_key)/sizeof(dh_pub_key[0]);i++){
  //  Serial.write(dh_pub_key[i]);
  //}

  f_public.close();

  /* DH private key */
  File f_private = FFat.open("/private.pem");
  if(!f_private){
    Serial.println("Failed opening DH private key file!");
    f_private.close();
    return;
  }
  
  while(f_private.available()){
    dh_priv_key[idx] = f_private.read();
    //Serial.write(f_private.read());
    idx++;
  }
  idx = 0;

  //for(int i=0;i<sizeof(dh_priv_key)/sizeof(dh_priv_key[0]);i++){
  //  Serial.write(dh_priv_key[i]);
  //}
  
  f_private.close();

  /* DHM public key */
  File f_dhm_public = FFat.open("/dhm_pub_key.pem");
  if(!f_dhm_public){
    Serial.println("Failed opening DHM public key file!");
    f_dhm_public.close();
    return;
  }
  
  while(f_dhm_public.available()){
    dhm_pub_key[idx] = f_dhm_public.read();
    //Serial.write(f_dhm_public.read());
    idx++;
  }

  //Serial.println();
  //for(int i=0;i<sizeof(dhm_pub_key)/sizeof(dhm_pub_key[0]);i++){
  //  Serial.write(dhm_pub_key[i]);
  //}
  
  f_dhm_public.close();

  Serial.println("All keys loaded successfully!");

  Serial.println("Starting BLE server...");

  BLEDevice::init("DEVICE_HOST_1");
  /* by default each characteristic can only hold a single value of 20 bytes
     this makes sures we can extend that value up to 517 bytes (+3 extra bytes) */  
  BLEDevice::setMTU(520);
  
  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());
  
  /* create data stream service from which */
  BLEService *authentication_service = pServer->createService(AUTHENTICATION_SERVICE_UUID);

  //authentication_service_state = BLE_SERVICE_INIT;

  BLECharacteristic *authentication_characteristic = authentication_service->createCharacteristic(AUTHENTICATION_CHAR_UUID,
                                                                                  BLECharacteristic::PROPERTY_READ | 
                                                                                  BLECharacteristic::PROPERTY_WRITE |
                                                                                  BLECharacteristic::PROPERTY_NOTIFY); /* |
                                                                                  BLECharacteristic::PROPERTY_INDICATE);*/

  //authentication_char_state = BLE_CHAR_INIT;                                                                 

  /* driver characteristics values are only updated after the device host establishes a connection to its master gateway */
  //temp_characteristic->setValue(NULL);
  //light_characteristic->setValue(NULL);
  // temp_service->start();
  // light_service->start();

  authentication_characteristic->addDescriptor(new BLE2902());
  authentication_characteristic->setCallbacks(new CharacteristicCallbacks());

  //authentication_char_state = BLE_CHAR_AUTH_REQUIRED;

  // update internal device state 
  authentication_state = DH_AUTH_REQ;

  // update characteristic value with its state
  authentication_characteristic->setValue("0x15");

  authentication_service->start();
  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(AUTHENTICATION_SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);  // functions that help with iPhone connections issue
  pAdvertising->setMinPreferred(0x12);
   
  BLEDevice::startAdvertising();

  Serial.println("Device host online waiting for authentication");
}

void loop() {
  /*
  switch(STATE){

    case WAITING_SESSION:
      break;
    case
  } 
    // notify changed value
    if (deviceConnected) {
        pCharacteristic->setValue((uint8_t*)&value, 4);
        pCharacteristic->notify();
        value++;
        delay(3); // bluetooth stack will go into congestion, if too many packets are sent, in 6 hours test i was able to go as low as 3ms
    }
    // disconnecting
    if (!deviceConnected && oldDeviceConnected) {
        delay(500); // give the bluetooth stack the chance to get things ready
        pServer->startAdvertising(); // restart advertising
        Serial.println("start advertising");
        oldDeviceConnected = deviceConnected;
    }
    // connecting
    if (deviceConnected && !oldDeviceConnected) {
        // do stuff here on connecting
        oldDeviceConnected = deviceConnected;
    }
 
   
  switch(data_stream_char_state){
    case BLE_CHAR_RX_READY:
      data_stream_char_state = BLE_CHAR_RX_READY;
      break;
    
    
  }
  if(data_stream_char_state == BLE_CHAR_STANDBY){
    data_stream_char_state = BLE_CHAR_RX_READY;
    data_stream_characteristic->setValue((uint8_t) data_stream_char_state,1);
  }
  

  
  
  if(deviceConnected){
    data_steam_characteristic->notify();  
  }
  
  ld.turnOn();
  */
  delay(1000);
}

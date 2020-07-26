
#include "FFat.h"
#include <esp_partition.h>

// this program write the dhm server public key into the ESP32 FFAT partition as a .pem file

unsigned char server_pub_key[] = "-----BEGIN PUBLIC KEY-----\n"\
                                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U+HuvytA+pBpT9beiE4\n"\
                                "GlqdFskzdwz7TVyC3z6nf2zYGO1MGqmc+EZvAM3kDrL3MOiaeaWQu+FmWcko+wAI\n"\
                                "4nOUNJZVz0Z+GphRJXY/Z6TceMmz/Bc/D0tudA2ChBwu35ztFcpkqwV0+0ZVygti\n"\
                                "mvV8gPfXzuXaVYDO4fWuoa22yzCTc+jGpN1yD6CjcourkNZu969spBbfjCyEiExo\n"\
                                "B4ZL5sMk/yNBYWJc/SM9j7mCJwU+CtakcALIBAAY4J7b/rYiYi63Ix8KB/83n09K\n"\
                                "f4ODdj7Hx6l8LUoVOU+cDQgYZgvHxeaG8Lud57SJoRiJUdxaaAV83lyWrYAeCYeM\n"\
                                "bQIDCgCx\n"\
                                "-----END PUBLIC KEY-----\n";

void partloop(esp_partition_type_t part_type) {
  esp_partition_iterator_t iterator = NULL;
  const esp_partition_t *next_partition = NULL;
  iterator = esp_partition_find(part_type, ESP_PARTITION_SUBTYPE_ANY, NULL);
  while (iterator) {
     next_partition = esp_partition_get(iterator);
     if (next_partition != NULL) {
        Serial.printf("partition addr: 0x%06x; size: 0x%06x; label: %s\n", next_partition->address, next_partition->size, next_partition->label);  
     iterator = esp_partition_next(iterator);
    }
  }
}


void setup() {
  Serial.begin(115200); 
  Serial.setDebugOutput(true);

/*
  Serial.println("Partition list:");
  partloop(ESP_PARTITION_TYPE_APP);
  partloop(ESP_PARTITION_TYPE_DATA);
*/

  if(!FFat.begin(true)){
    Serial.println("Mount Failed");
    return;
  }
  
  Serial.println("File system mounted successfully");

/*
  Serial.printf("Total space: %10lu\n", FFat.totalBytes());
  Serial.printf("Free space: %10lu\n", FFat.freeBytes());
*/

/********** WRITE PUBLIC KEY ************/ 
  
  File fpublic = FFat.open("/dhm_pub_key.pem", FILE_WRITE);
  
  if(!fpublic){
    Serial.println("Failed to open file for writting");
    fpublic.close();
    return;
  }
  
  if(!fpublic.print("-----BEGIN PUBLIC KEY-----\n"\
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7U+HuvytA+pBpT9beiE4\n"\
                    "GlqdFskzdwz7TVyC3z6nf2zYGO1MGqmc+EZvAM3kDrL3MOiaeaWQu+FmWcko+wAI\n"\
                    "4nOUNJZVz0Z+GphRJXY/Z6TceMmz/Bc/D0tudA2ChBwu35ztFcpkqwV0+0ZVygti\n"\
                    "mvV8gPfXzuXaVYDO4fWuoa22yzCTc+jGpN1yD6CjcourkNZu969spBbfjCyEiExo\n"\
                    "B4ZL5sMk/yNBYWJc/SM9j7mCJwU+CtakcALIBAAY4J7b/rYiYi63Ix8KB/83n09K\n"\
                    "f4ODdj7Hx6l8LUoVOU+cDQgYZgvHxeaG8Lud57SJoRiJUdxaaAV83lyWrYAeCYeM\n"\
                    "bQIDCgCx\n"\
                    "-----END PUBLIC KEY-----\n"
    )){
    Serial.println("File write failed");
    fpublic.close();
    return;
  }
  fpublic.close();
  
  File fpublic1 = FFat.open("/dhm_pub_key.pem");

   if(!fpublic1){
    Serial.println("Failed to open file for reading");
    fpublic1.close();
    return;
  }

  Serial.println("File Content:");
 
  while(fpublic1.available()){
    Serial.write(fpublic1.read());
  }
  fpublic1.close();
}

void loop() { }

#include "FFat.h"
#include <esp_partition.h>

// this program write the public/private key pair into the ESP32 FFAT partition as a .pem file

// 2048 bit private key as recommended by NIST 
unsigned char pub_key[] = "-----BEGIN PUBLIC KEY-----\n"\
                          "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBY/fwdDgFLCyOpQ5dI6+Y1\n"\
                          "+eVn9KfA1GsauCAsByZfHIaIkA3fx+/46m4nH4s7hcSjwUEQfNKUIW6AjCCnKwsg\n"\
                          "h2IWbxDzNHL+w3GNkjg8EdAhRUAXVzAELTGI6bgP4x/zeXVXCCQ43ddz8fArgaRw\n"\
                          "5VJjJ9YO3MHvO5bdRvUI6NmO4ZEN0ieohQnx4RYsV9JkVStBno+83+kFriqal5IU\n"\
                          "ckCZHEtiv+eH0602iraa1RwFvpgMF5V6KIILoqteTVZy2uuB4zrCRGjh23g0yu6K\n"\
                          "yld9Ps2dc5xiqsfPB550v1EpgvXPYiQ0rrhqw3/PUI13zyV0OoAcx4xTQgSgzdol\n"\
                          "AgMBAAE=\n"\
                          "-----END PUBLIC KEY-----\n";

unsigned char priv_key[] = "-----BEGIN RSA PRIVATE KEY-----\n" \
                          "MIIEowIBAAKCAQBY/fwdDgFLCyOpQ5dI6+Y1+eVn9KfA1GsauCAsByZfHIaIkA3f\n" \
                          "x+/46m4nH4s7hcSjwUEQfNKUIW6AjCCnKwsgh2IWbxDzNHL+w3GNkjg8EdAhRUAX\n" \
                          "VzAELTGI6bgP4x/zeXVXCCQ43ddz8fArgaRw5VJjJ9YO3MHvO5bdRvUI6NmO4ZEN\n" \
                          "0ieohQnx4RYsV9JkVStBno+83+kFriqal5IUckCZHEtiv+eH0602iraa1RwFvpgM\n" \
                          "F5V6KIILoqteTVZy2uuB4zrCRGjh23g0yu6Kyld9Ps2dc5xiqsfPB550v1EpgvXP\n" \
                          "YiQ0rrhqw3/PUI13zyV0OoAcx4xTQgSgzdolAgMBAAECggEANlh0m/GvjHpy/q0O\n" \
                          "ODQHVDMVi1R3FWUjOx/yVbDQGAk9hywhrOVWgPX46t9ykZjxKuebqkvv9RItf0cT\n" \
                          "scKxet3yYqzU9xCyoS4NrFz9BoICTi8SIq7V3dcThv7jrqAPJQqpQ8rvA+NF7cJz\n" \
                          "3r2/BEqm83KiYFUkAcqsKNlqTlPbLkito4Zvh+sUjnPdj0KbyhNGiTI/WZfUQyG2\n" \
                          "aSBCxI8tvvALsbBAKXpgzZfMnjInGxf3G2rgik1Tq9ypkt5qQXiqBPkxlbTi71t9\n" \
                          "DbE/6z7ngU0ls8QUsMmCdVFdbTQS4NTyqp0xyWbDjoWnEsbiYOVKBl1wwoMDKLKv\n" \
                          "HTCByQKBgQCm9HFp9tjqiruhOmzswXcQhZJJqzrslWw2tqFkEF5/JHtdzkvh3oql\n" \
                          "AYgf07WadT9L+8AJavgi1z21BHNq5eeVcW18QbatdYAu3SHc9hnaShhuexD16Sui\n" \
                          "LYg2MAX6LeXWR7aLDkUNXaA4Z1ehj0L0nwZQsrwQHjddQbxJwdqvBwKBgQCIdLmv\n" \
                          "6MCL3hl24aRqsVpzNvL6lPbUZS7o4J8HEzfvouZhi0+o5Py3RmDGJgyavvsPhcWw\n" \
                          "7me9uTqdyfFJTOoNM4GMYfCP6qrDuGmLoUJyszMTcQNdEKXS2dFMyiiAgQW3sajh\n" \
                          "oR6LiJ6UwV0RvThBE2Dem88qq2xXD6SP7Px2cwKBgQCJEAcH8kJ0kr6lB10jJVUF\n" \
                          "OFM3rZ5rWeSEKnzmtFWP1bh9833yiYuTGWXSkzD1BCqZy60FTk818zTSpjvG18W+\n" \
                          "t2cl6qD5WIyKbLp/N39T6R6TnO74o5tRwkWgDt7pW8Ljnu4qzOU9qs59X8Hefcl/\n" \
                          "IArEN2gTZ2sWYYAdoUtSAwKBgB9V/tZgsubryBk+1A0UUVsoAUB+OPipi8461wo+\n" \
                          "5ZeIZzN7VH3KqCZGaS7Xygk3VlxIMg/hj71H7igSGfDlUtJZQ6TDUQUbtL9heAty\n" \
                          "qtnAQThzuXwDuLDlCGWD/y0TdAatK8U0xNjyNMigZwkN1P9MvfAhA8AewbB0jSvo\n" \
                          "Fkn1AoGBAI7FeXEkWFC/dMyn/2kAqvveAEbPanFhvkbziAnOqHK9E2QIY/vTQKBr\n" \
                          "G0KI5Y+DdJdxihqFx3rxvg2zFkuy8f0lMLrup95EHngIGUL6MkmsU0F8knLQG5d+\n" \
                          "oCRZsJAKFjDL3ybnr31QKWRvmKE6a5euma63URfD0CFIyEPcLHc3\n"  \
                          "-----END RSA PRIVATE KEY-----\n";

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
  
  File fpublic = FFat.open("/public.pem", FILE_WRITE);
  
  if(!fpublic){
    Serial.println("Failed to open file for writting");
    fpublic.close();
    return;
  }
  
  if(!fpublic.print("-----BEGIN PUBLIC KEY-----\n"\
                    "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBY/fwdDgFLCyOpQ5dI6+Y1\n"\
                    "+eVn9KfA1GsauCAsByZfHIaIkA3fx+/46m4nH4s7hcSjwUEQfNKUIW6AjCCnKwsg\n"\
                    "h2IWbxDzNHL+w3GNkjg8EdAhRUAXVzAELTGI6bgP4x/zeXVXCCQ43ddz8fArgaRw\n"\
                    "5VJjJ9YO3MHvO5bdRvUI6NmO4ZEN0ieohQnx4RYsV9JkVStBno+83+kFriqal5IU\n"\
                    "ckCZHEtiv+eH0602iraa1RwFvpgMF5V6KIILoqteTVZy2uuB4zrCRGjh23g0yu6K\n"\
                    "yld9Ps2dc5xiqsfPB550v1EpgvXPYiQ0rrhqw3/PUI13zyV0OoAcx4xTQgSgzdol\n"\
                    "AgMBAAE=\n"\
                    "-----END PUBLIC KEY-----\n"
    )){
    Serial.println("File write failed");
    fpublic.close();
    return;
  }
  fpublic.close();
  
  File fpublic1 = FFat.open("/public.pem");

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

/********** WRITE PRIVATE KEY ************/ 


 File fprivate = FFat.open("/private.pem", FILE_WRITE);
  
  if(!fprivate){
    Serial.println("Failed to open file for writting");
    fprivate.close();
    return;
  }
  
  if(!fprivate.print("-----BEGIN RSA PRIVATE KEY-----\n" \
                    "MIIEowIBAAKCAQBY/fwdDgFLCyOpQ5dI6+Y1+eVn9KfA1GsauCAsByZfHIaIkA3f\n" \
                    "x+/46m4nH4s7hcSjwUEQfNKUIW6AjCCnKwsgh2IWbxDzNHL+w3GNkjg8EdAhRUAX\n" \
                    "VzAELTGI6bgP4x/zeXVXCCQ43ddz8fArgaRw5VJjJ9YO3MHvO5bdRvUI6NmO4ZEN\n" \
                    "0ieohQnx4RYsV9JkVStBno+83+kFriqal5IUckCZHEtiv+eH0602iraa1RwFvpgM\n" \
                    "F5V6KIILoqteTVZy2uuB4zrCRGjh23g0yu6Kyld9Ps2dc5xiqsfPB550v1EpgvXP\n" \
                    "YiQ0rrhqw3/PUI13zyV0OoAcx4xTQgSgzdolAgMBAAECggEANlh0m/GvjHpy/q0O\n" \
                    "ODQHVDMVi1R3FWUjOx/yVbDQGAk9hywhrOVWgPX46t9ykZjxKuebqkvv9RItf0cT\n" \
                    "scKxet3yYqzU9xCyoS4NrFz9BoICTi8SIq7V3dcThv7jrqAPJQqpQ8rvA+NF7cJz\n" \
                    "3r2/BEqm83KiYFUkAcqsKNlqTlPbLkito4Zvh+sUjnPdj0KbyhNGiTI/WZfUQyG2\n" \
                    "aSBCxI8tvvALsbBAKXpgzZfMnjInGxf3G2rgik1Tq9ypkt5qQXiqBPkxlbTi71t9\n" \
                    "DbE/6z7ngU0ls8QUsMmCdVFdbTQS4NTyqp0xyWbDjoWnEsbiYOVKBl1wwoMDKLKv\n" \
                    "HTCByQKBgQCm9HFp9tjqiruhOmzswXcQhZJJqzrslWw2tqFkEF5/JHtdzkvh3oql\n" \
                    "AYgf07WadT9L+8AJavgi1z21BHNq5eeVcW18QbatdYAu3SHc9hnaShhuexD16Sui\n" \
                    "LYg2MAX6LeXWR7aLDkUNXaA4Z1ehj0L0nwZQsrwQHjddQbxJwdqvBwKBgQCIdLmv\n" \
                    "6MCL3hl24aRqsVpzNvL6lPbUZS7o4J8HEzfvouZhi0+o5Py3RmDGJgyavvsPhcWw\n" \
                    "7me9uTqdyfFJTOoNM4GMYfCP6qrDuGmLoUJyszMTcQNdEKXS2dFMyiiAgQW3sajh\n" \
                    "oR6LiJ6UwV0RvThBE2Dem88qq2xXD6SP7Px2cwKBgQCJEAcH8kJ0kr6lB10jJVUF\n" \
                    "OFM3rZ5rWeSEKnzmtFWP1bh9833yiYuTGWXSkzD1BCqZy60FTk818zTSpjvG18W+\n" \
                    "t2cl6qD5WIyKbLp/N39T6R6TnO74o5tRwkWgDt7pW8Ljnu4qzOU9qs59X8Hefcl/\n" \
                    "IArEN2gTZ2sWYYAdoUtSAwKBgB9V/tZgsubryBk+1A0UUVsoAUB+OPipi8461wo+\n" \
                    "5ZeIZzN7VH3KqCZGaS7Xygk3VlxIMg/hj71H7igSGfDlUtJZQ6TDUQUbtL9heAty\n" \
                    "qtnAQThzuXwDuLDlCGWD/y0TdAatK8U0xNjyNMigZwkN1P9MvfAhA8AewbB0jSvo\n" \
                    "Fkn1AoGBAI7FeXEkWFC/dMyn/2kAqvveAEbPanFhvkbziAnOqHK9E2QIY/vTQKBr\n" \
                    "G0KI5Y+DdJdxihqFx3rxvg2zFkuy8f0lMLrup95EHngIGUL6MkmsU0F8knLQG5d+\n" \
                    "oCRZsJAKFjDL3ybnr31QKWRvmKE6a5euma63URfD0CFIyEPcLHc3\n"  \
                    "-----END RSA PRIVATE KEY-----\n"
    )){
    Serial.println("File write failed");
    fprivate.close();
    return;
  }
  fprivate.close();
  
  File fprivate1 = FFat.open("/private.pem");

   if(!fprivate1){
    Serial.println("Failed to open file for reading");
    fprivate1.close();
    return;
  }

  Serial.println("File Content:");
 
  while(fprivate1.available()){
    Serial.write(fprivate1.read());
  }
  fprivate1.close();
 
}

void loop() { }
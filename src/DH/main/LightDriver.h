#define LED 5

#define SERVICE_UUID "874f41ac-b692-4d02-90fc-a41cfadf141f"

#define READ_CHAR_UUID "9930cc28-648e-4769-a8ce-301823dd84dc"
#define WRITE_CHAR_UUID "97cde1dd-730f-41e5-9c50-b8132148c759"

class LightDriver{

  typedef enum {
    DRIVER_INIT,
    DRIVER_RUNNING,
    DRIVER_ERROR_BAD_BRIGHTNESS_VALUE,
  } driver_state; 

  typedef enum {
    SENSOR_ON,
    SENSOR_OFF
  } sensor_state;

  private:

  boolean confidentiality = false;  /* confidentiality flag set at the deployment stage by the DD A3C 
                                     * the confidentiality property may be changed based on the confidentiality flag of 
                                     *  the access token issued by the DD A3C to the client and finally to this DD
                                     */
  boolean light_state;  /* status of the LED  */
  int light_brightness; /* brightness of the LED between 0 and 10 */
  driver_state driver_status;

  // string representation of the driver api to be sent to the DH endpoint GW. Such attributes are then visible to proprly authenticated clients 
  String driver_api_str = "[turnOn(),turnOff(),increaseBrightness(),decreaseBrightness(),setBrightness()]"; 

  public:

  const unsigned char *private_key = (unsigned char *)
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEAiSGXp45FZTghRw+cpXoKbiW1pkR+d1RB5F8/vnGmNLJW7TZW\n"
  "loqNsaAymvQnK7K40nlFTMhv4lgk+4ABDslpXbtNI7PySX7RicAIK+t0wsItUZoM\n"
  "r3eA8MxwR9rX40b++aAVAgTqRxxqs9GEHT5K9i6VZ/OsnjU80Wgd8q3Ykp0J6sb0\n"
  "cg49PH4vT0NE7Wo3Q5PPEvHZ12jXx6dcJ8ti46ZkHTbe931XabZEatcL7Ya22Hek\n"
  "ZZ2YQsYopX+3be4cGG+Ox7x7GT068wCbFrMvwDRcm3Xos9MfhbmTK+2RfH5r9fyi\n"
  "8RzOKl/G5owSlBmxKrBM2SxfxZap+M4sv4cXtwIDAQABAoIBABBMy+gAw0LqzxnR\n"
  "Qz9wKDk7hkIDNj0c6NAqejs66xSsdiSwJs6yHXGVpy5AAz/weIOcIp6j3Ji8/Xhf\n"
  "mMCXNE0N7Hdn9k7CIkoLZ21BCZn01soyU3uv6sW0p0wDOVIsqDYnzxd0WhylxhEl\n"
  "wFxxgRuOIfg/QK91iIsjoxurimiyz1vypz7Tgb3zn4GDA2xaUlQ9R9cmKn3+8MoV\n"
  "97O1MLONzNQan4GT3KxKGWGHxQttB7s5qhfTiBNFa7Ejq7cJh9ESS80z1r0hBBGc\n"
  "K2A9qRJvd9cNbFN+HyYB57oNvPal8o9jd31wl7aCXSKgMphgAOM1bFQx1tEcqAPM\n"
  "H8EjOFECgYEA/UnDdavOA/qttqWQtUuB21BZETlMWivxfbxbmNo8obqi46xtquJS\n"
  "VgknpqF+PtS/Inn1UdNnSuk4VQGCKkcK4TFwfouTZBGozjttk7ySQZBk5Bauke53\n"
  "F6F8kgvfn0AAGkpSwbqXexrcAf6XlF2JKfyjA+bxw74VAmgKfvZWom0CgYEAipl0\n"
  "cBGtxOAaCSfOqSeZ7S8/3ZTU9tMNLfl1owriA9jP9eUSbynCwcAH0xoV37k2a4ud\n"
  "0XAMHBhe/6h7DwB2juEkoSz9YnNPxKMPag7W0JtzYW6WdbKMHuQjUIXQl1NV/V3o\n"
  "4aSsdXbl6KDL5oAXa6q4+X80REE7B0/0ZWGCLDMCgYEA0BDkK6myVrp6MOvY79TT\n"
  "G6HpSKjU+83VVwCADhRYclKqtHRUsmewU1S56bwHxP1m9Z9R0qHi3DqxN8NBdhFd\n"
  "8pd2Xb2ymiWXkbJn1VC2pH1FI8kuJlrKIfNaLW7riBo++1nKmbH59fqeeFT3l70u\n"
  "i/sovm/ccnuXLp7g4GLj0BECgYAmG2kTQxkW71LZP5OnmJbOytXxc3FWZ9LQ2CzK\n"
  "5jwcOKl8/z2hSMcehFDibuKiv4bB7QI4SmlZ9C1yd31WM5dlU2vB0N/eCLxe4UJk\n"
  "s63Gb2c627AMrkmuWKWJBzHB2Yzj+8UC/UbZiRZPbp6BQqit1qPDHYFeXtz+9rHI\n"
  "ihXDVwKBgQCJDAYDHosDgiPU2GZToIdN5zFi61iku/Twn6/tuHQXXrIVzJ+yPs3z\n"
  "6EYbz5qL+vz3vUSvUnvL01WesAOqyu2G2RoXxhFgP+3nmOHKb3Qy4b2Dic+wxfS2\n"
  "QNnMsfW1S1/DCVpuu+MWICfuwcXI9DcVqjPg8L1v9k6nNr5GFLTFoQ==\n"
  "-----END RSA PRIVATE KEY-----\n";
  
  const unsigned char * const public_key = (unsigned char *)
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiSGXp45FZTghRw+cpXoK\n"
  "biW1pkR+d1RB5F8/vnGmNLJW7TZWloqNsaAymvQnK7K40nlFTMhv4lgk+4ABDslp\n"
  "XbtNI7PySX7RicAIK+t0wsItUZoMr3eA8MxwR9rX40b++aAVAgTqRxxqs9GEHT5K\n"
  "9i6VZ/OsnjU80Wgd8q3Ykp0J6sb0cg49PH4vT0NE7Wo3Q5PPEvHZ12jXx6dcJ8ti\n"
  "46ZkHTbe931XabZEatcL7Ya22HekZZ2YQsYopX+3be4cGG+Ox7x7GT068wCbFrMv\n"
  "wDRcm3Xos9MfhbmTK+2RfH5r9fyi8RzOKl/G5owSlBmxKrBM2SxfxZap+M4sv4cX\n"
  "twIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

  const unsigned char * const a3c_dd_public_key = (unsigned char *)
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAot1PwGGDA/Qy1DHRdWaX\n"
  "HWVK9feNQYJ7lAAQeyQV7oBEdl9Fy4VmeQPfQdb/POtIxr7LKolcNs7PIAWWD6f5\n"
  "zDTEXwNMrvA4jehZCuFChL+WOnxN8EAtLzRLtmlPLSoLZ8eU1f+5kce2JDXOXdVM\n"
  "2K0YFdbvuUG+DogpXrQfzUyznq2AzafkpWzjbFfIMK3LLUWEdv59tYAFY+Lm0JYq\n"
  "j99WliCp30DknZKkROA933XBnMEbEPlD9cncB2jF0ft9Ek1FSXV63xxiF0GYWbQd\n"
  "Ypc8VvCaCKNh7y/IP+d6OSzNdh7ALp8lold8TGiaWMOLK0MirL7FeOguU2PFtj8h\n"
  "LwIDCgCx\n"
  "-----END PUBLIC KEY-----\n";
  
  std::string uuid_dd = "dab28026b85882feba58b342ab8f592f";
  std::string uuid_a3c_dd = "ee3aeedd1bc30c4d2472d638064151c4";

  unsigned char* getDriverDescription(){
    return (unsigned char*)driver_api_str.c_str();
  }

  size_t getPubKeyLen(){
    return strlen( (char*)public_key);
  }

  size_t getPrivKeyLen(){
    return strlen( (char*)private_key);
  }

  size_t getA3CKeyLen(){
    return strlen( (char*)a3c_dd_public_key);
  }

  size_t getDescLen(){
    return driver_api_str.length();
  }


  /* ----------------------- API Functions -----------------------*/
  
  void turnOn(){
    digitalWrite(LED, LOW);   // turn the LED on (HIGH is the voltage level)
    light_state = true;
    Serial.println("Light turned ON");
  }
  void turnOff(){
    digitalWrite(LED, HIGH);    // turn the LED off by making the voltage LOW   
    light_state = false;
    Serial.println("Light turned OFF");
  }

  boolean getStatus(){
    return driver_status;
  }
  
  void increaseBrightness(){
    if(light_brightness == 10){
      //Serial.println("Brightness value is already at maximum!");
      return;
    }else 
      light_brightness++;
    //Serial.println("Brightness increased");
  }

  void decreaseBrightness(){
    if(light_brightness == 0){
      //Serial.println("Brightness value is already at minumum!");
      return;
    }else 
      light_brightness--;
    //Serial.println("Brightness decreased");
  }

  driver_state setBrightness(int value){
    if(value < 0 || value > 10){
      //Serial.println("Invalid brightness value! Must be integer between 0 and 10");
      return DRIVER_ERROR_BAD_BRIGHTNESS_VALUE;
    }
    
  }

  LightDriver(){
    driver_status = DRIVER_INIT;
    pinMode(LED, OUTPUT); /* initialize digital pin LED_BUILTIN as an output. */
    digitalWrite(LED, HIGH);    // turn the LED off by making the voltage LOW 
    light_state = false;
    light_brightness = 5;
    driver_status = DRIVER_RUNNING;
  }

};

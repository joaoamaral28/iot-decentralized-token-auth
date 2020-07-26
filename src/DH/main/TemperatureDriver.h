 #ifdef __cplusplus
  extern "C" {
 #endif
 
  uint8_t temprature_sens_read();
 
#ifdef __cplusplus
}
#endif
 
uint8_t temprature_sens_read();


#define SERVICE_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"

#define READ_CHAR_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define WRITE_CHAR_UUID "d3d79032-72a0-4249-a56e-96eeeca88a5b"

class TemperatureDriver{

  typedef enum {
    DRIVER_INIT,
    DRIVER_RUNNING,
    DRIVER_CALIBRATION_OK,
    DRIVER_UNIT_SET_OK,
    DRIVER_ERROR_CALIBRATION_FAILED,
    DRIVER_ERROR_BAD_CONFIG,
    DRIVER_ERROR_BAD_UNIT_CONFIG
  } driver_state; 

  private:

  // string representation of the driver api to be sent to the DH endpoint GW. Such attributes are then visible to proprly authenticated clients 
  String driver_api_str = "[readValue(),calibrateSensor(),setUnits()]"; 

  boolean confidentiality = false;  /* confidentiality flag set at the deployment stage by the DD A3C 
                                     * the confidentiality property may be changed based on the confidentiality flag of 
                                     *  the access token issued by the DD A3C to the client and finally to this DD
                                     */

  driver_state driver_status;/* state of the driver */
  uint8_t temp_value;   /* variable to hold the temperature value of the sensor */ 
  // int precision;    /* precision of the readings */
  char temp_units;  /* units in which the data is to be displayed */ 

  public:

  const unsigned char * const private_key = (unsigned char *)
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEAkvxIfXMBo1qVmGIL41uW1eZEfBTx6FWblVisCzi0VWBNAmsQ\n"
  "bRyvssp1Nd4+Dx5Gkjxww+wgtmzckOtoP/71Jp3Nlj8rlzBJSx4AzxMB6KyIp56E\n"
  "bAx9K6HxSUFnEfPzPQ9ZyZG2ABd+jMiAYA/KMD2nu7p1PM5mcd7aL8GpBUL0GE+H\n"
  "xMZtgiJEGlxSbNVdYUu7Wi2kXJruvna0mEiazI55myEm6xFux4WfPa62YmaVE+ej\n"
  "JrQ6JBS6VIJwhR/oI5n8yffVj4E22GkyG7qDUvnd0KuCLyOzeCsvMuD7IXd8SP+A\n"
  "+otutWe5O0T9nT2hNEvxfxAWYZhQHRIOhaU0IQIDAQABAoIBAQCAkw8WLbQRIPwb\n"
  "AClGCKg5E+R0Zh32Dmy6h4Z3inK0/DhhFSaZS66lx1QgevfuYZ157kT2HWfALBoE\n"
  "6ueWk3/+96sO8tM+vY5fly899HKHBeXEOnW7znDv6gkW+48dtTfhAbyZBk0eZ27b\n"
  "18f0P9utt0EyhjhnqGUU1swlWlJvtnO9K2GavKrRh6/kZrYIzAgb/JzxJJHLliiL\n"
  "9u4cgw/ZgDZzpcwsRFqtmaMTHFh0WHHghe+DLalzPZUUyUzmzecn+UcBcjtGggbe\n"
  "HD2PG9wyDJuJqBbdaVlv9U9iiLJtbxBnpfpxlH0ipZp9XLA5Hsx6xbaHAYE+F7+F\n"
  "7lpGTMvBAoGBAPjUgNFXIYy7YygvC3mOR0hIL7ZwP+PvfWFWqHJAmOM2Dx0iNn8T\n"
  "3f2xXvbIRSZJHMw6tTQf5GO2rq45fVPqdUA2ozpR+QvNO6zRLUNcqb2DBC0Lgraw\n"
  "/BrEAeFhyFKCVGUhItmley0u2vvfIcnblmgTjIz/DlI1BW5T0unj4+APAoGBAJc4\n"
  "hcTnr5IMU4BSYvLOryi16vc0qDgaDoeb0pKQVv6NNXvSLCy5wwWw0VhzahU0Sq+D\n"
  "/tkD929lAftyjTausgY2IA+6ZrBbCmQ7PBhHWOKdjJm8WuDCh6oGMJg7KUi12d2J\n"
  "yhFT/x0yqDBOrFKYpWl0sJjQourUXbwko4b+5HjPAoGAR31eSUbcR7+qvGfPxyu+\n"
  "hSDgPG1Bne43upiYKsMuadElRHyI5bfChtnH6+UcIOTOlkqjtwcWqiNZSosP2+U3\n"
  "rKxF90KH6AEeDQfIFltwFReoQnzVIEH3HIWF+MgMMtBpCOkdRyTJH/EfT1ALOCCT\n"
  "tPEw5218IthC6DDDHxmvZbcCgYAlGwBv5W3GR3IBzbVr4N1H/wNtryULxxEDo2+S\n"
  "+QnvohSakmK2gspgzhdAPems1EzzLk9NTtTbJ4zJ9zzBSzJxpbxOP63M3jn5iDNh\n"
  "vbgIuyHx4y7lcbY6ORSZdgLWTZDs9E952wOBVZnBaLyN89i6vKBMjv064+swLElX\n"
  "6ZmELwKBgQCR/6eUBKwaeCaNv0n7CppPJQ5aloteZjaaNTmQO/rP0HzA5h8oZ8ya\n"
  "lg6QSRuTicsTOCHNsvMAOZDhMYQsqddznT6tQpv1deaLTL+fp2SprUSStTkNB3TZ\n"
  "7TNMJEaKv6nGZwJ/mqC/j7Fx62xacYzKd5Pz5h3egIz2duVRcqJvZg==\n"
  "-----END RSA PRIVATE KEY-----\n";
  
  const unsigned char * const public_key = (unsigned char *)
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvxIfXMBo1qVmGIL41uW\n"
  "1eZEfBTx6FWblVisCzi0VWBNAmsQbRyvssp1Nd4+Dx5Gkjxww+wgtmzckOtoP/71\n"
  "Jp3Nlj8rlzBJSx4AzxMB6KyIp56EbAx9K6HxSUFnEfPzPQ9ZyZG2ABd+jMiAYA/K\n"
  "MD2nu7p1PM5mcd7aL8GpBUL0GE+HxMZtgiJEGlxSbNVdYUu7Wi2kXJruvna0mEia\n"
  "zI55myEm6xFux4WfPa62YmaVE+ejJrQ6JBS6VIJwhR/oI5n8yffVj4E22GkyG7qD\n"
  "Uvnd0KuCLyOzeCsvMuD7IXd8SP+A+otutWe5O0T9nT2hNEvxfxAWYZhQHRIOhaU0\n"
  "IQIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

  const unsigned char * const a3c_dd_public_key = (unsigned char * )
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAot1PwGGDA/Qy1DHRdWaX\n"
  "HWVK9feNQYJ7lAAQeyQV7oBEdl9Fy4VmeQPfQdb/POtIxr7LKolcNs7PIAWWD6f5\n"
  "zDTEXwNMrvA4jehZCuFChL+WOnxN8EAtLzRLtmlPLSoLZ8eU1f+5kce2JDXOXdVM\n"
  "2K0YFdbvuUG+DogpXrQfzUyznq2AzafkpWzjbFfIMK3LLUWEdv59tYAFY+Lm0JYq\n"
  "j99WliCp30DknZKkROA933XBnMEbEPlD9cncB2jF0ft9Ek1FSXV63xxiF0GYWbQd\n"
  "Ypc8VvCaCKNh7y/IP+d6OSzNdh7ALp8lold8TGiaWMOLK0MirL7FeOguU2PFtj8h\n"
  "LwIDCgCx\n"
  "-----END PUBLIC KEY-----\n";

  std::string uuid_dd = "f17a1fe9d42b711c463cdad54e5db6f0";
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

  uint8_t readValue(){
    uint8_t val = temprature_sens_read();
    if(temp_units == 'C'){
      return ((temp_value - 32) / 1.8);
    }
    Serial.print("Temperature value (F): ");
    Serial.println(val);
    return val;
  }
  
  driver_state calibrateSensor(){
    return DRIVER_CALIBRATION_OK;
  }

  // change reading measurement units of the sensor to either celcius or fahrenheit
  driver_state setUnits(unsigned char temp_unit){
    if((temp_units != 'C') && (temp_units != 'F' )){
      driver_status = DRIVER_ERROR_BAD_UNIT_CONFIG;
    }else{
      temp_units = temp_unit;
      driver_status = DRIVER_UNIT_SET_OK;
    }
    return driver_status;
  }
  
  TemperatureDriver(){
    driver_status = DRIVER_INIT;
    if((temp_units != 'C') && (temp_units != 'F' )){
      driver_status = DRIVER_ERROR_BAD_UNIT_CONFIG;
    }else{
      temp_units = temp_units;
      driver_status = DRIVER_RUNNING;
    }
  }
  
};

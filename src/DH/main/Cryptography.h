#include <string>
#include <sstream>
#include <algorithm>
#include <map>


//#include "mbedtls/md5.h"

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

#include "base64.h"

/*
struct AuthenticationTicket{
  std::string secret;
  struct pub {
    std::string dh_id; // 128 bit uuid of the device 
    std::string dh_addr; // BLE address respresentation 
    std::string owner_id; // 128 bit uuid of the ticket owner 
    std::string access_rights; // set of permissions the ticket owner has over the device 
    std::string ticket_lifetime; // validity of the ticket in question 
    std::string details; // context specific additional information 
  } pub;
  std::string signature;
  boolean valid;
};
*/

// transforms the resulting md5 hash of the host/driver public key into a compatible ble service 128 bit uuid 
/*
std::string md5toUUID(unsigned char* md5hash){
  std::string h(reinterpret_cast<char*>(md5hash));
  return h.substr(0,8) + "-" + h.substr(8,4) + "-" + h.substr(12,4) + "-" + h.substr(16,4) + "-" + h.substr(20,12);
}
*/

// digest a given public key to a compatible ble service 128 bit uuid
/*
std::string pubKeyToUUID(unsigned char* pub_key){
  
  unsigned char output[32];
  int ilen = sizeof(pub_key) - 1;
  mbedtls_md5(pub_key, ilen, output);
  for(int i = 0; i < 16; i++){
    Serial.print(output[i],HEX);
  }
  return md5toUUID(output);
}
*/


static bool filterChar(char c){
    switch(c){
    case '{':
    case '}':
    case ' ':
    case '\'':
        return true;
    default:
        return false;
    }
}


boolean decryptAES(unsigned char* input,unsigned char* output, unsigned char* iv, unsigned char* key, size_t input_len){
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int ret = 0;
  
  mbedtls_aes_setkey_dec( &aes, key, 256 );
  if((ret=mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, input_len, iv, input, output))!=0){
    Serial.println("[Error] Failed AES CBC encryption"); 
    mbedtls_aes_free( &aes ); 
    return false;
  }

  //Serial.println("decryptAES() output");
  //for(int i=0;i<16;i++) Serial.println(output[i]);

  Serial.println("[OK] AES CBC decryption successful");
  mbedtls_aes_free( &aes );
  return true;
  
}

size_t encryptAES(unsigned char* input,unsigned char* output, unsigned char* original_iv, unsigned char* key, size_t input_len){
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init( &ctr_drbg );

  unsigned char iv[16];
  int ret = 0;
  
  //init IV
  if((ret=mbedtls_ctr_drbg_random(&ctr_drbg,iv,16))!=0){
    Serial.println("[Error] Failed to generate IV");
    return 1 ;
  }

//Serial.println("encryptAES() IV");
//for(int i=0;i<16;i++) Serial.println(int(iv[i]));

//  memcpy(original_iv, iv, sizeof(original_iv));
  for(int i=0;i<16;i++) original_iv[i] = iv[i];
  
  mbedtls_aes_setkey_enc( &aes, key, 256 );
  ret = 0;
  if((ret=mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, input_len, iv, input, output))!=0){
    Serial.println("[Error] Failed AES CBC encryption"); 
    mbedtls_aes_free( &aes ); 
    return 1;
  }

  //Serial.println("encryptAES() output");
  //for(int i=0;i<128;i++) Serial.println(output[i]);

  Serial.println("[OK] AES CBC encryption successful");
  mbedtls_aes_free( &aes );
  return ret;
}

size_t generateSessionKey(unsigned char nonce1[],unsigned char nonce2[],unsigned char key[],unsigned char output[],
                      size_t nonce1_len, size_t nonce2_len, size_t key_len, size_t output_len){

  int ret = 0;
  mbedtls_sha256_context ctx;  
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0); // SHA-256, not 224 
  
  mbedtls_sha256_update_ret(&ctx, nonce1, nonce1_len);
  mbedtls_sha256_update_ret(&ctx, nonce2, nonce2_len);
  mbedtls_sha256_update_ret(&ctx, key, key_len);
  
  if((ret=mbedtls_sha256_finish_ret(&ctx, output))!=0){
    Serial.println("[Error] Failed finishing hash 256 procedure");
    mbedtls_sha256_free(&ctx);
    return ret;
  }
  Serial.println("[OK] Derived session key was digested successfully");
  mbedtls_sha256_free(&ctx);
  return ret;

}

size_t decryptRSA(unsigned char enc_data[], unsigned char plaintext[], unsigned char priv_key[], size_t enc_data_len, size_t key_len, size_t plaintext_len){

  int ret = 0;  
  mbedtls_pk_context pk_ctx;
  mbedtls_pk_init( &pk_ctx );
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init( &ctr_drbg );
  
  if((ret=mbedtls_pk_parse_key(&pk_ctx, priv_key, key_len,NULL,NULL))!=0){
    Serial.println("[Error] Failed while parsing RSA private key");
    //return false;
  }
  Serial.println("[OK] Private RSA key parse!");

  size_t olen = 0;

  if((ret=mbedtls_pk_decrypt(&pk_ctx,enc_data,enc_data_len,plaintext,&olen, plaintext_len,NULL,NULL))!=0){
    //printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
    char tbs[500];
    sprintf(tbs, "-0x%04x\n", -ret);
    Serial.println(tbs);
    char buf[500];
    mbedtls_strerror(ret,buf, sizeof(buf));
    Serial.println(buf);
    
    Serial.println("[Error] Failed calculating RSA decryption");
    return false;        
  }

  Serial.println("[OK] RSA Decryption!");

  return olen;
  
}

size_t signRSA(unsigned char message[], unsigned char signature[], unsigned char priv_key[], size_t message_len, size_t key_len){

  int ret = 0;
  const char *pers = "mbedtls_pk_sign";
  mbedtls_pk_context pk_ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  unsigned char hash[32];
  size_t sign_len = 0;

  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_pk_init( &pk_ctx );

  if((ret=mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *)pers,strlen(pers)))!=0){
      Serial.println("[Error] Failed while seeding the random number generator!");
      return false;
    }
  Serial.println("[OK] RNG Seeding!");

  /* parse RSA private key */
  if((ret=mbedtls_pk_parse_key(&pk_ctx, priv_key, key_len,NULL,NULL))!=0){
    Serial.println("[Error] Failed while parsing RSA private key");
    /*
    char buf[500];
    mbedtls_strerror(ret,buf, sizeof(buf));
    Serial.println(buf);
    */
    return false;
  }
  Serial.println("[OK] Private RSA key parse!");

  /*
   * Compute the SHA-256 hash of the input message,
   * then calculate the signature of the hash.
   */
  if((ret=mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),message,message_len-1,hash))!=0){
    Serial.println("[Error] Failed calculating message digest");
    return false;
  }
    
  Serial.println("[OK] Message digest!");
  
  if((ret = mbedtls_pk_sign( &pk_ctx, MBEDTLS_MD_SHA256, hash, 0, signature, &sign_len,mbedtls_ctr_drbg_random, &ctr_drbg))!= 0){
    Serial.println("[Error] Failed calculating message signature");
    return false;
  }
  
  Serial.println("[OK] Message signature!");

  mbedtls_pk_free( &pk_ctx );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

  return sign_len;
  
}


boolean verifyRSA(unsigned char* message,unsigned char* signature, unsigned char* pub_key, size_t len_msg, size_t len_sign, size_t len_key){

  int ret = 1;
  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  unsigned char hash[32];
  
  mbedtls_pk_context pubk_ctx;
  mbedtls_pk_init( &pubk_ctx );

  // parse RSA public key 
  if((ret=mbedtls_pk_parse_public_key(&pubk_ctx,pub_key,len_key))!=0){
    Serial.println("[Error] Failed while parsing RSA public key");
     /*
    char tbs[500];
    sprintf(tbs, "-0x%04x\n", -ret);
    Serial.println(tbs);
    char buf[500];
    mbedtls_strerror(ret,buf, sizeof(buf));
    Serial.println(buf);
    */
    return false;
  }
    
  Serial.println("[OK] Public RSA key parse!");

  /*
   * Compute the SHA-256 hash of the message and
   * verify the signature
   */  
  if((ret=mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),message,len_msg,hash))!=0){
    Serial.println("[Error] Failed calculating message digest");
    return false;
  }
/*
  for(int i=0;i<sizeof(hash)/sizeof(hash[0]);i++){
    Serial.println(int(hash[i]));
  }
*/
  
  Serial.println("[OK] Message digest!");   

  /* NOTE: Use mbedtls_pk_verify_ext( MBEDTLS_PK_RSASSA_PSS, ... ) to verify RSASSA_PSS signatures. */
  if( ( ret = mbedtls_pk_verify(&pubk_ctx,MBEDTLS_MD_SHA256,hash,0,signature,len_sign))!=0){
    Serial.println("[Error] Failed validating signature");
    
    Serial.println(ret);
    char buf[500];
    mbedtls_strerror(ret,buf, sizeof(buf));
    Serial.println(buf);
    
    return false;
  }

  Serial.println("[OK] Signature valid!");  

  mbedtls_pk_free(&pubk_ctx);

  return true;

}

/*
AuthenticationTicket parseTicket(std::string ticket, unsigned char* dhm_pub_key, size_t dhm_pub_key_len){

  AuthenticationTicket auth_ticket;

  ticket.erase(std::remove_if(ticket.begin(), ticket.end(), &filterChar), ticket.end());                        
                                                                             
  // parse SECRET part 
  size_t s_pos1 = ticket.find("secret");
  size_t s_pos2 = ticket.find(',',s_pos1);
  
  std::string secret_part = ticket.substr(s_pos1,s_pos2-s_pos1);
  
  if(s_pos2 > ticket.length()){ // catch case if secret field is the last section of the dict, in which case the comma is never found
     secret_part.erase(secret_part.end()-1 );
  }
 
  size_t dot_pos = secret_part.find(':');
  std::string secret_key = secret_part.substr(dot_pos+1, secret_part.length()-dot_pos);
  std::vector<BYTE> decoded_key = base64_decode(secret_key);
  auth_ticket.secret = secret_key;
  /*
  for(int i=0;i<decoded_key.size();i++){
    Serial.println((int)decoded_key[i]);
  }
  */
 /* 
  Serial.println("SECRET");
  Serial.println(secret_key.c_str());

  // parse SIGNATURE part
  size_t sig_pos1 = ticket.find("signature");
  size_t sig_pos2 = ticket.find(',',sig_pos1);

  std::string signature_part = ticket.substr(sig_pos1,sig_pos2-sig_pos1);
  
  if(sig_pos2 > ticket.length()){ // catch case if secret field is the last section of the dict, in which case the comma is never found
     signature_part.erase(signature_part.end()-1 );
  }

  size_t dot_pos1 = signature_part.find(':');
  std::string signature = signature_part.substr(dot_pos1+1, signature_part.length()-dot_pos1);
  const char * sig = signature.c_str();
  Serial.println("SIGNATURE");
  Serial.println(sig);

  auth_ticket.signature = signature;

  // parse PUBLIC part    
  size_t pub_pos1 = ticket.find("public");
  size_t pub_pos2 = ticket.find(',',pub_pos1);

  std::string public_part = ticket.substr(pub_pos1+7,pub_pos2-(pub_pos1+7));
  
  if(pub_pos2 > ticket.length()){ // catch case if public field is the last section of the dict, in which case the comma is never found
     public_part.erase(public_part.end()-1 );
  }

  Serial.println("PUBLIC");
  Serial.println(public_part.c_str());

  // byte vector containing the dictionary format of the ticket public part 
  std::vector<BYTE> decoded_public = base64_decode(public_part);
  /*
  for(int i=0; i<decoded_public.size();i++){
    Serial.write(decoded_public[i]);
  }
  Serial.println();
  */


  /* Validate the signature of the ticket before proceeding any further. 
   * The signature was performed over the concatenation of the public 
   * and the secret parts of the ticket
   */
   /*
  unsigned char msg[decoded_key.size() + decoded_public.size()];
  for(int i=0;i<decoded_key.size();i++){
    msg[i] = decoded_key[i];
  }
  for(int i=0;i<decoded_public.size();i++){
    msg[i+decoded_key.size()] = decoded_public[i];
  }

  // msg[decoded_key.size() + decoded_public.size() + 1] = 0;

/* CORRECT
  Serial.println("MESSAGE");
  for(int i=0;i<sizeof(msg)/sizeof(msg[0]);i++){
    Serial.println(int(msg[i]));
  }
*/
 
  //std::vector<BYTE> s = base64_decode(signature);

/* CORRECT 
  for(int i=0;i<s.size();i++){
    Serial.println(int(s[i]));
  }
*/

  /*
  unsigned char signature_array[s.size()];
  //signature_array[s.size() + 1] = 0;
  for(size_t i=0; i<s.size();i++){
    signature_array[i] = s[i];
  }
  
  size_t sign_len = sizeof(signature_array)/sizeof(signature_array[0]);

  //Serial.println(sign_len);
  size_t msg_len = sizeof(msg)/sizeof(msg[0]);

  / validate ticket signature 
  if(!verifyRSA(msg, signature_array, dhm_pub_key, msg_len, sign_len, dhm_pub_key_len)){
    Serial.println("[Error] Invalid signature!");
    auth_ticket.valid = false;
    return auth_ticket;
  }  

  auth_ticket.valid = true;


  std::string pub(decoded_public.begin()+1, decoded_public.end()-1);
  pub.erase(std::remove_if(pub.begin(), pub.end(), &filterChar), pub.end());  // remove ' char and white spaces                    

  Serial.println(pub.c_str());

  std::istringstream iss(pub);
  std::string t;
  
  while(std::getline(iss,t,',')){     
      size_t pos = t.find(':');
      std::string key = t.substr(0,pos);
      std::string value = t.substr(pos+1);
      Serial.print("Key: ");
      Serial.print(key.c_str());
      Serial.print(" Value: ");
      Serial.println(value.c_str());
      if(key=="dh_id"){
        auth_ticket.pub.dh_id = value;
      }else if(key=="dh_addr"){
        auth_ticket.pub.dh_addr = value;
      }else if(key=="owner_id"){
        auth_ticket.pub.owner_id = value;
      }else if(key=="access_rights"){
        auth_ticket.pub.access_rights = value;
      }else if(key=="ticket_lifetime"){
        auth_ticket.pub.ticket_lifetime = value;
      }else if(key=="details"){
        auth_ticket.pub.details = value;
      }else{
        Serial.print("Unknown key parsed ");
        Serial.println(key.c_str());
        Serial.println("Key and value to be ignored!");
      }               
  }
  
  return auth_ticket;
  
}
*/

/* 
 * function responsible for validating the recevied authentication ticket
 * the validation process is done by verifying the signature part of the ticket
 * if the signature (which must be from the DHM of the device running this code)
 * matches its DHM then its confirmed as valid
 */
//boolean validateAuthenticationTicket(std::string ticket, unsigned char* dhm_pub_key, unsigned char* dh_priv_key, size_t dhm_pub_key_len, size_t dh_priv_key_len  ){
boolean validateAuthenticationTicket(unsigned char* ticket_priv, size_t priv_len, std::string ticket_pub, unsigned char* ticket_sign, 
                                    size_t sign_len,unsigned char* ticket_nonce, unsigned char* dhm_pub_key, unsigned char* dh_priv_key, 
                                    size_t dhm_pub_key_len, size_t dh_priv_key_len  ){

  // base64 decode the ticket public part
  std::vector<unsigned char> decoded_pub = base64_decode(ticket_pub);
  std::string s(decoded_pub.begin(), decoded_pub.end());
  //Serial.println(s.c_str());

  // signature is performed over the decoded public and private parts of the ticket
  size_t doc_len = decoded_pub.size() + sign_len;
  unsigned char doc[doc_len];
  
  for(int i=0;i<priv_len;i++){
    doc[i] = ticket_priv[i];
  }
  for(int i=0;i<decoded_pub.size();i++){
    doc[i+priv_len] = decoded_pub[i];
  }

  // validate ticket signature 
  if(!verifyRSA(doc, ticket_sign, dhm_pub_key, doc_len, sign_len, dhm_pub_key_len)){
    Serial.println("[Error] Invalid signature!");
    return false;
  }  

  // parse the ticket public part and validate its contents (dh_id, dh_addr, etc.)
  // < TODO >

  
  // string parser converting dictionary string reprsentation to ticket struct
  //AuthenticationTicket auth_ticket = parseTicket(ticket, dhm_pub_key, dhm_pub_key_len);
  //return auth_ticket.valid;
  return true;
  /* check ticket public parts, namely dh_id, dh_addr to guarantee that this DH is the correct ticket recipient */
  /* < TODO > */

  // decode base64 session key */
  //std::vector<BYTE> decoded_secret = base64_decode(auth_ticket.secret); /* < TODO > double check if the b64 encoding is really necessary for the private part */

  /* convert back to unsigned char */ 
  /*
  unsigned char decoded_secret_[decoded_secret.size()];
  for(int i=0;i<decoded_secret.size();i++){
    decoded_secret_[i] = decoded_secret[i];
  }
  */

  /* decrypt secret key using dh private key */
  /*
  unsigned char secret_key[MBEDTLS_MPI_MAX_SIZE]; // buffer to store the decryption result 
  size_t enc_key_len = sizeof(decoded_secret_)/sizeof(decoded_secret_[0]); 
  size_t session_key_len = decryptRSA(decoded_secret_, secret_key, dh_priv_key, enc_key_len, dh_priv_key_len);

  for(int i=0;i<sizeof(secret_key)/sizeof(secret_key[0]);i++){
    Serial.println((int) secret_key[i]);
  }
  
  return auth_ticket.valid;
  */

  /* Generate random nonce2 */

  
  /* Compute derived session key K' */
  // unsigned char session_key = digest(K,R1,R2);


  return false;

}

/*
//boolean validateAuthenticationTicket(std::string ticket, unsigned char* dhm_pub_key, unsigned char* dh_priv_key, size_t dhm_pub_key_len, size_t dh_priv_key_len  ){
boolean validateDriverAuthenticationTicket(unsigned char* ticket_priv, size_t priv_len, std::string ticket_pub, unsigned char* ticket_sign, 
                                    size_t sign_len,unsigned char* ticket_nonce, unsigned char* dhm_pub_key, unsigned char* dh_priv_key, 
                                    size_t dhm_pub_key_len, size_t dh_priv_key_len  ){


  // signature is performed over the decoded public and private parts of the ticket
  size_t doc_len = ticket_pub.size() + sign_len;
  unsigned char doc[doc_len];
  
  for(int i=0;i<priv_len;i++){
    doc[i] = ticket_priv[i];
  }
  for(int i=0;i<ticket_pub.size();i++){
    doc[i+priv_len] = ticket_pub[i];
  }

  // validate ticket signature 
  if(!verifyRSA(doc, ticket_sign, dhm_pub_key, doc_len, sign_len, dhm_pub_key_len)){
    Serial.println("[Error] Invalid signature!");
    return false;
  }  

  // parse the ticket public part and validate its contents (dh_id, dh_addr, etc.)
  // < TODO >

  
  // string parser converting dictionary string reprsentation to ticket struct
  //AuthenticationTicket auth_ticket = parseTicket(ticket, dhm_pub_key, dhm_pub_key_len);
  //return auth_ticket.valid;
  return true;
}
*/

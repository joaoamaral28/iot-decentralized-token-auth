/* 
 *  base64 library modification provided by stackoverflow user LihO 
 *  at https://stackoverflow.com/a/13935718. This implementation no 
 *  longer carries the burden of the original library that worked 
 *  with binary data stored within std::string objects 
 */

#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
typedef unsigned char BYTE;

std::string base64_encode(BYTE const* buf, unsigned int bufLen);
std::vector<BYTE> base64_decode(std::string const&);

#endif

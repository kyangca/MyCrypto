#ifndef AES_HPP /* Include guard */
#define AES_HPP

#include <string>
#include <stdint.h>

std::string aes_128_single_encrypt(std::string ptext, std::string key);
std::string aes_128_single_decrypt(std::string ctext, std::string key);

#endif /* AES_HPP */

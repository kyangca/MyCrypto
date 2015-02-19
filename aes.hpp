#ifndef AES_HPP /* Include guard */
#define AES_HPP

#include <string>
#include <stdint.h>

std::string aes_128_single_encrypt(std::string ptext, std::string key);
std::string aes_128_single_decrypt(std::string ctext, std::string key);

// Temporarily made methods available outside of aes.cpp for testing
// purposes.
std::string aes_128_keyexpand(std::string key);
std::string shift_rows_forward(std::string str);
std::string shift_rows_backward(std::string str);
std::string mix_columns_forward(std::string str);
std::string mix_columns_backward(std::string str);

#endif /* AES_HPP */

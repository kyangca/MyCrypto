/*
 * Header file: util.hpp
 * ---------------------------------------
 * This header file is meant to contain "utility" functions that assist
 * in the encryption and decryption process, but are not direct implementations
 * of encryption, decryption, or modes of operation.
 * Examples include a string padding function to safely pad plaintext
 * to a length which is evenly divisible into blocks of the appropriate size.
 * In addition, any "standard" includes that will be useful in just about
 * any file will be included here.
 */

#ifndef UTIL_HPP
#define UTIL_HPP

#include <iostream>
#include <string>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>

/* Methods to implement the PKCS7 padding algorithm. */
std::string pkcs7_pad(std::string input, int len);
std::string pkcs7_unpad(std::string input);

/* Other convenience methods */
std::string str_xor(std::string str1, std::string str2);

#endif //UTIL_HPP

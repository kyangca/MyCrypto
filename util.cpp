/*
 * Source file: util.cpp
 * ---------------------------------------
 * Provides an implementation of the various utility methods
 * promised in util.hpp.
 */

#include "util.hpp"
#include <stdio.h>

using namespace std;

/*
 * Method: pkcs7_pad
 * Description: Takes a string and adds padding to it,
 * according to the PKCS#7 Padding Scheme.
 * Arguments:
 *   - input: a string which needs to be padded.  Cannot be
 *     empty.
 *   - len: an integer, the FINAL LENGTH to which input must
 *     be padded to.  Cannot be negative, less than the existing
 *     input's length, or greater than 256 + existing input's length,
 *     which is the max PKCS#7 can handle.
 */
string pkcs7_pad(string input, int len)
{
    if(input.empty())
    {
        throw invalid_argument("Cannot pad NULL string.");
    }
    else if(len <= 0)
    {
        throw invalid_argument("Cannot pad to 0 or negative length.");
    }
    else if(input.length() > len)
    {
        throw invalid_argument("Cannot pad to length less than original.");
    }
    else if(len - input.length() >= 256)
    {
        throw invalid_argument("PKCS7 padding can't pad more than 255 bytes.");
    }

    int diff = len - input.length();
    unsigned char padbyte = (unsigned char) diff;
    string result = input;
    for(int i = 0; i < diff; i++)
    {
        result.push_back(padbyte);
    }
    return result;
}

/*
 * Method: pkcs7_unpad
 * Description: Takes a string and removes any padding added by PKCS7, if
 * that padding exists.
 * Arguments:
 *   - input, the string to unpad.  If there is any padding, this method
 *     returns input, except without the padding.  If there isn't any,
 *     input will be returned as is.  In the exceedingly unfortunate event
 *     that input was not really padded, but the last couple of bytes
 *     just happened to be similar to padding, the last couple of bytes
 *     will probably be stripped.  I can't really think of a good way
 *     to prevent this, other than being careful when you call this...
 */
string pkcs7_unpad(string input)
{
    if(input.empty())
    {
        throw invalid_argument("Cannot unpad NULL string.");
    }
    string result;
    unsigned int last = (unsigned int)input[input.length() - 1];
    if(last > 255)
    {
        // Failed because PKCS7 can't pad more than 255.
        cout << "PKCS7 Unpad Failed" << endl;
        return input;
    }
    for(int i = last - 1; i > 0; i--)
    {
        if(input[input.length() - i] != input[input.length() - 1])
        {
            // Failed due to invalid padding
            cout << "PKCS7 Unpad Failed" << endl;
            return input;
        }
    }
    result = input.substr(0, input.length() - last);
    return result;
}

/*
 * Method: str_xor
 * Description: Takes two equal length strings and XORs each character
 * in the first with its corresponding character in the second to form
 * a third string.
 * Arguments:
 *   - str1, string, the first argument, must not be empty, and
 *     must be equal length with str2.
 *   - str2, string, the second argument, must not be empty, and
 *     must be same length as str1.
 */
string str_xor(string str1, string str2) 
{
    if(str1.empty() || str2.empty())
    {
        throw invalid_argument("Cannot XOR NULL string.");
    }
    else if(str1.size() != str2.size())
    {
        throw invalid_argument("Cannot XOR strings of unequal length.");
    }
    string result = "";
    for(int i = 0; i < str1.size(); i++)
    {
        result.push_back(str1[i] ^ str2[i]);
    }
    return result;
}

/*
 * Method: hex_print
 * Description: Takes a string and prints it as a series of unsigned
 * hex characters.  Mostly for debugging purposes.
 * Argument:
 *   - str, string, the string that needs to be printed as a series of
 *     hex bytes
 */
void hex_print(string str)
{
    for(int i = 0; i < str.size(); i++)
    {
        printf(" %02x", (unsigned char)str[i]);
    }
    printf("\n");
}

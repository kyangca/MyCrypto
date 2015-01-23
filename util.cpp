/*
 * Source file: util.cpp
 * ---------------------------------------
 * Provides an implementation of the various utility methods
 * promised in util.hpp.
 */

#include "util.hpp"

using namespace std;

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
    cout << "Byte: " << padbyte << endl;
    string padding;
    padding.reserve(diff);
    for(int i = 0; i < diff; i++)
    {
        padding[i] = padbyte;
    }
    cout << "Pad: " << padding << endl;
    string result = input + padding;
    cout << "Result: " << hex << result << endl;
    return result;
}

string pkcs7_unpad(string input)
{
    if(input.empty())
    {
        throw invalid_argument("Cannot unpad NULL string.");
    }
    cout << "TODO" << endl;
    return NULL;
}
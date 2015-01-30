#include "aes.hpp"
#include "util.hpp"

const int AES_BLOCKSIZE = 16;
const int AES_128_KEYSIZE = 16;
const int AES_128_NUMKEYS = 44;

using namespace std;

string[] aes_128_keyexpand(string key);

string[] aes_128_keyexpand(string key)
{
    string result[AES_128_NUMKEYS];
    
}

string aes_128_single_encrypt(string ptext, string key)
{
    /* Argument Validation
     * Check to make sure nothing is NULL, and that all length restrictions
     * are satisfied. */
    if(ptext.empty())
    {
        throw invalid_argument("Cannot encrypt NULL plaintext.");
    }
    else if(key.empty())
    {
        throw invalid_argument("Cannot encrypt using NULL key.");
    }
    else if(key.length() != AES_128_KEYSIZE)
    {
        throw invalid_argument("AES128 requires a 128-bit (16-byte) key.");
    }
    else if(ptext.length() > AES_BLOCKSIZE)
    {
        throw invalid_argument("Plaintext too large for one 128-bit block.");
    }
    else if(ptext.length() < AES_BLOCKSIZE)
    {
        //TODO: Once pkcs7_pad works, just pad to block length.
        //For now, since it doesn't work, throw exception.
        //pkcs7_pad(ptext, AES_BLOCKSIZE - ptext.length());
        throw invalid_argument("Plaintext not exactly 128-bit block."); 
    }

    /* Key Expansion. */
    string[] expandkey = aes_128_keyexpand(key);
    return NULL;
}

string aes_128_single_decrypt(string ctext, string key)
{
    cout << "TODO" << endl;
    return NULL;
}

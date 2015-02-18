#include "aes.hpp"
#include "util.hpp"

const int AES_BLOCKSIZE = 16;
const int AES_128_KEYSIZE = 16;
const int AES_128_NUMKEYS = 44;
const int WORD_SIZE = 4;

// This is the S-box used to substitute bytes during encryption
// This is defined as part of the AES standard.
const unsigned char sbox_forward[256] = 
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// This contains all the round constants
// This is defined as part of the AES standard.
const unsigned char Rcon[256] = 
{
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

using namespace std;

// Prototypes for helper functions for AES encrypt/decryption
//string aes_128_keyexpand(string key);
string sub_bytes_forward(string str);
string shift_rows_forward(string str);
string mix_columns_forward(string str);
string add_round_key_forward(string arg, string expandkey, int roundno);

string add_round_key_forward(string arg, string expandkey, int roundno)
{
    if(arg.empty())
    {
        throw invalid_argument("Cannot add round key to NULL string");
    }
    else if(expandkey.empty())
    {
        throw invalid_argument("Cannot add round key to NULL string");
    }
    else if(arg.size() != AES_BLOCKSIZE)
    {
        throw invalid_argument("Invalid size for arg in add_round_key_forward");
    }
    else if(roundno < 0)
    {
        throw invalid_argument("Invalid round number for adding round key");
    }
    string roundkey = expandkey.substr(AES_BLOCKSIZE * roundno, AES_BLOCKSIZE * (roundno + 1));
    return str_xor(arg, roundkey);
}

string mix_columns_forward(string str)
{
    char mat[4][4], mixed[4][4];
    for(int i = 0; i < AES_BLOCKSIZE; i++)
    {
        // Write the initial input into a 4x4 matrix of characters
        // It is important to note that we must write column-wise
        mat[i % 4][i / 4] = str[i];
    }
    // Handle first row
    char temp;
    for(int i = 0; i < 4; i++)
    {
        temp = (char) (0x02 * mat[0][i]);
        temp = temp ^ (0x03 * mat[1][i]);
        temp = temp ^ mat[2][i];
        temp = temp ^ mat[3][i];
        mixed[0][i] = temp;
    }
    // Handle second row
    for(int i = 0; i < 4; i++)
    {
        temp = mat[0][i];
        temp = temp ^ (0x02 * mat[1][i]);
        temp = temp ^ (0x03 * mat[2][i]);
        temp = temp ^ mat[3][i];
        mixed[1][i] = temp;
    }
    // Handle third row
    for(int i = 0; i < 4; i++)
    {
        temp = mat[0][i];
        temp = temp ^ mat[1][i];
        temp = temp ^ (0x02 * mat[2][i]);
        temp = temp ^ (0x03 * mat[3][i]);
        mixed[2][i] = temp;
    }
    // Handle fourth row
    for(int i = 0; i < 4; i++)
    {
        temp = (char) (0x03 * mat[0][i]);
        temp = temp ^ mat[1][i];
        temp = temp ^ mat[2][i];
        temp = temp ^ (0x02 * mat[3][i]);
        mixed[3][i] = temp;
    }
    string result = "";
    for(int i = 0; i < AES_BLOCKSIZE; i++)
    {
        result.push_back(mixed[i % 4][i / 4]);
    }
    return result;
}

string shift_rows_forward(string str)
{
    if(str.empty())
    {
        throw invalid_argument("Cannot substitute NULL string");
    }
    else if(str.size() <= 0)
    {
        throw invalid_argument("Cannot substitute for invalid string length");
    }
    char mat[4][4];
    for(int i = 0; i < AES_BLOCKSIZE; i++)
    {
        // Write the initial input into a 4x4 matrix of characters
        // It is important to note that we must write column-wise
        mat[i % 4][i / 4] = str[i];
    }
    //TODO
    char a, b;
    // Shift the second row of the state matrix left one character
    a = mat[1][0];
    mat[1][0] = mat[1][1];
    mat[1][1] = mat[1][2];
    mat[1][2] = mat[1][3];
    mat[1][3] = a;
    // Shift the third row of the state matrix left two characters
    a = mat[2][0];
    b = mat[2][1];
    mat[2][0] = mat[2][2];
    mat[2][1] = mat[2][3];
    mat[2][2] = a;
    mat[2][3] = b;
    // Shift the fourth row of the state matrix left three characters
    // This is equivalent to right-shifting 1 character
    a = mat[3][3];
    mat[3][3] = mat[3][2];
    mat[3][2] = mat[3][1];
    mat[3][1] = mat[3][0];
    mat[3][0] = a;
    string result = "";
    for(int i = 0; i < AES_BLOCKSIZE; i++)
    {
        result.push_back(mat[i % 4][i / 4]);
    }
    return result;
}

string sub_bytes_forward(string str)
{
    if(str.empty())
    {
        throw invalid_argument("Cannot substitute NULL string");
    }
    else if(str.size() <= 0)
    {
        throw invalid_argument("Cannot substitute for invalid string length");
    }
    //char *result = (char *) calloc(strlen(str) + 1, sizeof(char));
    string result;
    uint8_t b;
    unsigned int r, c, idx;
    for(int i = 0; i < str.size(); i++)
    {
        // Retrieve the first 4 bits and the last 4 bits from the
        // current character.  The first 4 bits serve to determine
        // the row we use in the S-box, and the last 4 bits are the
        // column.
        b = (uint8_t)str[i];
        r = (int)((b & 0xF0) >> 4);
        c = (int)(b & 0x0F);
        // Need to inspect later for off-by-one error.
        idx = (16 * r) + c;
        // This is suspect conversion...
        result.push_back(sbox_forward[idx]);
    }
    return result;
}

string aes_128_keyexpand(string key)
{
    //const char *key_cstr = key.c_str();
    //char *result = (char *) calloc(WORD_SIZE, AES_128_NUMKEYS);
    //char *temp, *temp2;
    string result = "", temp, temp2;
    char c;
    // The first 4 words of the expanded key are just the exact
    // key that was given to us.  Copy the bytes over.
    for(int i = 0; i < AES_128_KEYSIZE; i++)
    {
        //result[i] = key_cstr[i];
        result.push_back(key[i]);
    }
    for(int i = 1; i <= 10; i++)
    {
        // Hold the last word of the 4-word block before this one
        //temp = (char *)calloc(5, sizeof(char));
        temp = result.substr((16*i)-4, 4);
        // Hold the first word of the 4-word block before this one
        //temp2 = (char *)calloc(5, sizeof(char));
        temp2 = result.substr((16*i)-16, 4);
        // Get the last word of the previous block of 4 words
        /*for(int j = 0; j < 4; j++)
        {
            temp[j] = result[(16*i)-4+j];
            temp2[j] = result[(16*i)-16+j];
        }*/
        // Apply a left circular shift to temp.
        c = temp[0];
        /*for(int j = 1; j < 4; j++)
        {
            temp[j-1] = temp[j];
        }
        temp[3] = c;*/
        temp = temp.substr(1);
        temp.push_back(c);
        // Perform a byte substitution using the forward S-box.
        temp = sub_bytes_forward(temp);
        // XOR with round constant
        temp[0] = temp[0] ^ (char)Rcon[i];
        // XOR with first word of the 4-word block before this one
        // This becomes the first word of the current 4-word block
        temp = str_xor(temp, temp2);
        temp2.clear();
        for(int j = 0; j < 4; j++)
        {
            //result[(16*i)+j] = temp[j];
            result.push_back(temp[j]);
            // Take advantage of this loop to get the second word
            // of the last 4-word block.
            //temp2[j] = result[(16*i)-12+i];
            //temp2.push_back(result[(16*i)-12+j]);
        }
        temp.clear();
        // Write the remaining three blocks of the current 4-word block.
        // There's probably a much more elegant and secure way to do
        // this, but right now that takes a back seat to functionality.
        for(int j = 1; j <= 3; j++)
        {
            /*// Calculate the jth block of the current 4-word block
            // (zero-indexed in this case) and write it
            temp = str_xor(temp, temp2);
            temp2.clear();
            for(int k = 0; k < 4; k++)
            {
                //result[(16*i)+(4*j)+k] = temp[k];
                result.push_back(temp[k]);
                // Copy the j+1th block of the last 4-word block
                //temp2[k] = result[(16*i)-(4*(j-1))+k];
                temp2.push_back(result[(16*i)-(4*(j-1))+k]);
            }*/
            for(int k = 0; k < 4; k++)
            {
                temp.push_back(result[(16*i)+(4*(j-1))+k]);
                temp2.push_back(result[(16*(i-1))+(4*j)+k]);
            }
            temp = str_xor(temp, temp2);
            for(int k = 0; k < 4; k++)
            {
                result.push_back(temp[k]);
            }
            temp.clear();
            temp2.clear();
        }
        //free(temp);
        //free(temp2);
        temp.clear();
        temp2.clear();
    }
    //string r = result;
    return result;
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
    string expandkey = aes_128_keyexpand(key);
    string result = add_round_key_forward(ptext, expandkey, 0);
    result = sub_bytes_forward(result);
    result = shift_rows_forward(result);
    result = mix_columns_forward(result);
    return result;
}

string aes_128_single_decrypt(string ctext, string key)
{
    cout << "TODO" << endl;
    return NULL;
}

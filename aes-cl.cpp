#include "aes.hpp"
#include "util.hpp"
#include <iostream>
#include <string>

using namespace std;

const int AES_BLOCKSIZE = 16;

string process_hex(string arg);

string process_hex(string arg)
{
    string temp;
    int val = 0;
    if(arg.length() % 3 != 0)
    {
        throw invalid_argument("Invalid length for input hex string.");
    }
    for(int i = 0; i < arg.length(); i += 3)
    {
        if(arg[i] < '0' || (arg[i] > '9' && arg[i] < 'a') || arg[i] > 'f')
        {
            throw invalid_argument("Unacceptable hex character");
        }
        if(arg[i+1] < '0' || (arg[i+1] > '9' && arg[i+1] < 'a') || arg[i+1] > 'f')
        {
            throw invalid_argument("Unacceptable hex character");
        }
        if(arg[i+2] != ' ')
        {
            throw invalid_argument("Unacceptable hex character");
        }
        if(arg[i] >= '0' && arg[i] <= '9')
        {
            val += 16 * (arg[i] - '0');
        }
        else
        {
            val += 16 * ((int)arg[i] - 87);
        }
        if(arg[i+1] >= '0' && arg[i+1] <= '9')
        {
            val += arg[i+1] - '0';
        }
        else
        {
            val += (int)arg[i+1] - 87;
        }
        temp.push_back((char) val);
        val = 0;
    }
    return temp;
}

int main()
{
    cout << "AES-128 Interactive Encrypt/Decrypt Tool" << endl;
    cout << "Encrypt or decrypt?  Enter 0 for encrypt, 1 for decrypt." << endl;
    string i;
    getline(cin, i);
    if(i[0] != '1' && i[0] != '0')
    {
        cerr << "error: invalid option specified" << endl;
        return 1;
    }
    else if(i[0] == '0')
    {
        string ptext, key, iv, ctext;
        cout << "Enter plaintext: " << endl;
        getline(cin, ptext);
        cout << "Enter key: " << endl;
        getline(cin, key);
        if(ptext.length() <= AES_BLOCKSIZE)
        {
            ctext = aes_128_single_encrypt(ptext, key);
        }
        else
        {
            cout << "Plaintext is longer than one block length.  Using CBC mode." << endl;
            cout << "Enter iv: " << endl;
            getline(cin, iv);
            ctext = aes_128_cbc_encrypt(ptext, key, iv);
        }
        cout << "The ciphertext in hex is: " << endl;
        hex_print(ctext);
        cout << "Naively printing the ciphertext results in: " << endl;
        cout << ctext << endl;
    }
    else
    {
        string ctext = "", key = "", iv, ptext;
        cout << "Enter ciphertext in hex (lowercase chars please)" << endl;
        cout << "For example, \"Bye\" should be entered as \"42 79 65\": " << endl;
        getline(cin, ctext);
        ctext.push_back(' ');
        ctext = process_hex(ctext);
        cout << "Enter key: " << endl;
        getline(cin, key);
        if(ctext.length() <= AES_BLOCKSIZE)
        {
            ptext = aes_128_single_decrypt(ctext, key);
        }
        else
        {
            cout << "Enter iv:" << endl;
            getline(cin, iv);
            ptext = aes_128_cbc_decrypt(ctext, key, iv);
        }
        //cout << "Attempting to depad plaintext under PKCS7.";
        //cout << "  If it doesn't work, nothing will happen." << endl;
        //ptext = pkcs7_unpad(ptext);
        cout << "The plaintext in hex is: " << endl;
        hex_print(ptext);
        cout << "Naively printing the plaintext results in: " << endl;
        cout << ptext << endl;
    }
    return 0;
}

#include "aes.hpp"
#include "util.hpp"
#include <iostream>
#include <string>

using namespace std;

string process_hex(string arg);

string process_hex(string arg)
{
    string temp;
    int val = 0;
    if(arg.length() % 2 != 0)
    {
        throw invalid_argument("Argument hex string must be even length");
    }
    for(int i = 0; i < arg.length(); i += 2)
    {
        if(arg[i] < '0' || (arg[i] > '9' && arg[i] < 'a') || arg[i] > 'f')
        {
            throw invalid_argument("Unacceptable hex character");
        }
        if(arg[i+1] < '0' || (arg[i+1] > '9' && arg[i+1] < 'a') || arg[i+1] > 'f')
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
        string ptext, key;
        cout << "Enter plaintext: " << endl;
        getline(cin, ptext);
        cout << "Enter key: " << endl;
        getline(cin, key);
        string ctext = aes_128_single_encrypt(ptext, key);
        cout << "The ciphertext in hex is: " << endl;
        hex_print(ctext);
        cout << "Naively printing the ciphertext results in: " << endl;
        cout << ctext << endl;;
    }
    else
    {
        string ctext = "", key = "", temp;
        cout << "Enter ciphertext in hex (lowercase chars please): " << endl;
        getline(cin, ctext);
        //hex_print(ctext);
        ctext = process_hex(ctext);
        //cout << "You got: \n";
        //cout << ctext << endl;
        cout << "Enter key: " << endl;
        getline(cin, key);
        string ptext = aes_128_single_decrypt(ctext, key);
        cout << "The plaintext in hex is: " << endl;
        hex_print(ptext);
        cout << "Naively printing the plaintext results in: " << endl;
        cout << ptext << endl;
    }
    return 0;
}

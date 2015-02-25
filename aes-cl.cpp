#include "aes.hpp"
#include "util.hpp"
#include <iostream>

using namespace std;

int main()
{
    cout << "AES-128 Interactive Encrypt/Decrypt Tool" << endl;
    cout << "Encrypt or decrypt?  Enter 0 for encrypt, 1 for decrypt." << endl;
    int i;
    cin >> i;
    if(i != 1 && i != 0)
    {
        cerr << "error: invalid option specified" << endl;
        return 1;
    }
    else if(i == 0)
    {
        string ptext, key;
        cout << "Enter plaintext: " << endl;
        cin >> ptext;
        cout << "Enter key: " << endl;
        cin >> key;
        string ctext = aes_128_single_encrypt(ptext, key);
        cout << "The ciphertext in hex is: " << endl;
        hex_print(ctext);
        cout << "Naively printing the ciphertext results in: " << endl;
        cout << ctext << endl;;
    }
    else
    {
        string ctext, key;
        cout << "Enter ciphertext: " << endl;
        cin >> hex >> ctext;
        hex_print(ctext);
        cout << "Enter key: " << endl;
        cin >> key;
        string ptext = aes_128_single_decrypt(ctext, key);
        cout << "The plaintext in hex is: " << endl;
        hex_print(ptext);
        cout << "Naively printing the plaintext results in: " << endl;
        cout << ptext << endl;
    }
    return 0;
}

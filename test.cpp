#include "util.hpp"
#include "aes.hpp"

using namespace std;

int pkcs7_pad_normal()
{
    string s = "TEST STRING";
    int len = s.length() + 4;
    string result;
    try
    {
        result = pkcs7_pad(s, len);
    }
    catch(...)
    {
        cerr << "error: pkcs7_pad threw exception when it shouldn't." << endl;
        cerr << "PKCS7 Padding Normal Functionality: FAIL" << endl;
        return 0;
    }
    if(result.compare("TEST STRING\x04\x04\x04\x04"))
    {
        cerr << "Returned: " << hex << result << endl;
        cerr << "error: pkcs7_pad returned incorrect string." << endl;
        cerr << "PKCS7 Padding Normal Functionality: FAIL" << endl;
        return 0;
    }
    else
    {
        cout << "PKCS7 Padding Normal Functionality: PASS" << endl;
        return 1;
    }
}

int main(int argc, char **argv)
{
    pkcs7_pad_normal();
    return 0;
}

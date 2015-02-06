#include "util.hpp"
#include "aes.hpp"

using namespace std;

int test_pkcs7_pad_normal()
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
        cerr << "<<<PKCS7 Padding Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    if(result.compare("TEST STRING\x04\x04\x04\x04") != 0)
    {
        cerr << "Returned: " << hex << result << endl;
        cerr << "error: pkcs7_pad returned incorrect string." << endl;
        cerr << "<<<PKCS7 Padding Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    else
    {
        cout << "<<<PKCS7 Padding Normal Functionality: PASS>>>" << endl;
        return 1;
    }
}

int test_str_xor_normal()
{
    char *s1 = "hit the bull's eye";
    char *s2 = "the kid don't play";
    char *expected = "\x1c\x01\x11\x00\x1f\x01\x01\x00\x06\x1a\x02KSSP\t\x18\x1c";
    char *got = str_xor(s1, s2, 18);
    if(strcmp(got, expected) != 0)
    {
        cout << "<<<String XOR Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    cout << "<<<String XOR Normal Functionality: PASS>>>" << endl;
    return 1;
}

int test_aes_128_encrypt_normal()
{
    // These are just placeholder values.
    string ptext = "YELLOW SUBMARINE";
    string key = "THISKEYIS16BYTES";
    // TODO: Currently if I can compile this and run the encryption function
    // and get any result, with no errors occurring along the way, I'll count
    // it as a success.
    string result = aes_128_single_encrypt(ptext, key);
    cout << "<<<AES 128 Single-block Encryption Normal Functionality: PASS>>>" << endl;
    return 1;
}

int main(int argc, char **argv)
{
    int num_tests = 3;
    int passed_tests = 0;
    cout << "BEGINNING AES TEST SUITE..." << endl;
    cout << "TOTAL NUMBER OF TESTS TO BE CARRIED OUT: " << num_tests << endl;
    passed_tests += test_pkcs7_pad_normal();
    passed_tests += test_str_xor_normal();
    passed_tests += test_aes_128_encrypt_normal();
    cout << "TESTING FINISHED" << endl;
    cout << "TOTAL NUMBER OF PASSED TESTS: " << passed_tests << endl;
    cout << "TOTAL NUMBER OF FAILED TESTS: " << (num_tests - passed_tests) << endl;
    cout << "PERCENTAGE OF PASSED TESTS: " << (passed_tests * 100.0 / num_tests) << endl;
    return 0;
}

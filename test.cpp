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
    if(strcmp(result.c_str(), "TEST STRING\x04\x04\x04\x04") != 0)
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
    string s1 = "hit the bull's eye";
    string s2 = "the kid don't play";
    string temp = "";
    temp.push_back('\0');
    string expected = "\x1c\x01\x11";
    expected += temp;
    expected += "\x1f\x01\x01";
    expected += temp;
    expected += "\x06\x1a\x02KSSP\t\x18\x1c";
    string got = str_xor(s1, s2);
    if(expected.compare(got) != 0)
    {
        cout << "<<<String XOR Normal Functionality: FAIL>>>" << endl;
        cerr << "Got is: " << got << endl;
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
    string expected = "\x7C\xA6\xD7\xFB\xEC\x58\x1F\x16\x86\xD8\xDF\x93\xA6\x3B\x5C\x29";
    if(expected.compare(result) != 0)
    {
        cerr << "E: ";
        hex_print(expected);
        cerr << "R: ";
        hex_print(result);
        cerr << "<<<AES 128 Single-block Encryption Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    cout << "<<<AES 128 Single-block Encryption Normal Functionality: PASS>>>" << endl;
    return 1;
}

int test_aes_128_keyexpand()
{
    /*
     * This example and resulting expanded key, according to
     * http://openschemes.com/2010/03/03/fun-with-aes-128-example-encryption-with-aes-trainer/
     * comes from an official FIPS document.
     * I had to do some trickery to handle embedded NULLs.
     */
    string temp = "";
    temp.push_back('\0');
    string key = temp + "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    string result = aes_128_keyexpand(key);
    string expected = temp + "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    expected += "\xD6\xAA\x74\xFD\xD2\xAF\x72\xFA\xDA\xA6\x78\xF1\xD6\xAB\x76\xFE";
    expected += "\xB6\x92\xCF\x0B\x64\x3D\xBD\xF1\xBE\x9B\xC5";
    expected += temp;
    expected += "\x68\x30\xB3\xFE";
    expected += "\xB6\xFF\x74\x4E\xD2\xC2\xC9\xBF\x6C\x59\x0C\xBF\x04\x69\xBF\x41";
    expected += "\x47\xF7\xF7\xBC\x95\x35\x3E\x03\xF9\x6C\x32\xBC\xFD\x05\x8D\xFD";
    expected += "\x3C\xAA\xA3\xE8\xA9\x9F\x9D\xEB\x50\xF3\xAF\x57\xAD\xF6\x22\xAA";
    expected += "\x5E\x39\x0F\x7D\xF7\xA6\x92\x96\xA7\x55\x3D\xC1\x0A\xA3\x1F\x6B";
    expected += "\x14\xF9\x70\x1A\xE3\x5F\xE2\x8C\x44\x0A\xDF\x4D\x4E\xA9\xC0\x26";
    expected += "\x47\x43\x87\x35\xA4\x1C\x65\xB9\xE0\x16\xBA\xF4\xAE\xBF\x7A\xD2";
    expected += "\x54\x99\x32\xD1\xF0\x85\x57\x68\x10\x93\xED\x9C\xBE\x2C\x97\x4E";
    expected += "\x13\x11\x1D\x7F\xE3\x94\x4A\x17\xF3\x07\xA7\x8B\x4D\x2B\x30\xC5";
    if(result.compare(expected) != 0)
    {
        cerr << "<<<AES 128 Key Expansion Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    else
    {
        cout << "<<<AES 128 Key Expansion Normal Functionality: PASS>>>" << endl;
        return 1;
    }
}

int test_aes_128_shift_rows_forward()
{
    string temp = "\xb1\x53\x27\x97\x30\x19\xe8\x67\xcb\xe6\xe1\x88\x54\x05\xa5\xc1";
    string result = shift_rows_forward(temp);
    string expected = "\xb1\x19\xe1\xc1\x30\xe6\xa5\x97\xcb\x05\x27\x67\x54\x53\xe8\x88";
    if(expected.compare(result) != 0)
    {
        cerr << "E: ";
        hex_print(expected);
        cerr << "G: ";
        hex_print(result);
        cerr << "<<<AES 128 ShiftRows Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    cout << "<<<AES 128 ShiftRows Normal Functionality: PASS>>>" << endl;
    return 1;
}

int test_aes_128_mix_columns_forward()
{
    string temp = "\xb1\x19\xe1\xc1\x30\xe6\xa5\x97\xcb\x05\x27\x67\x54\x53\xe8\x88";
    string result = mix_columns_forward(temp);
    string expected = "\x72\x7a\x29\xa9\x63\x84\x25\x26\xc2\xcf\x29\xaa\x3d\x59\x4f\x4c";
    if(expected.compare(result) != 0)
    {
        cerr << "E: ";
        hex_print(expected);
        cerr << "G: ";
        hex_print(result);
        cerr << "<<<AES 128 MixColumns Normal Functionality: FAIL>>>" << endl;
        return 0;
    }
    cout << "<<<AES 128 MixColumns Normal Functionality: PASS>>>" << endl;
    return 1;
}

int main(int argc, char **argv)
{
    int num_tests = 6;
    int passed_tests = 0;
    cout << "BEGINNING AES TEST SUITE..." << endl;
    cout << "TOTAL NUMBER OF TESTS TO BE CARRIED OUT: " << num_tests << endl;
    passed_tests += test_pkcs7_pad_normal();
    passed_tests += test_str_xor_normal();
    passed_tests += test_aes_128_encrypt_normal();
    passed_tests += test_aes_128_keyexpand();
    passed_tests += test_aes_128_shift_rows_forward();
    passed_tests += test_aes_128_mix_columns_forward();
    cout << "TESTING FINISHED" << endl;
    cout << "TOTAL NUMBER OF PASSED TESTS: " << passed_tests << endl;
    cout << "TOTAL NUMBER OF FAILED TESTS: " << (num_tests - passed_tests) << endl;
    cout << "PERCENTAGE OF PASSED TESTS: " << (passed_tests * 100.0 / num_tests) << endl;
    return 0;
}

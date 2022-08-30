#include <iostream>
#include <string>
using std::string;
using std::wstring;

#include <cryptopp/cryptlib.h>
using CryptoPP::byte;

// funtion definitions
/* convert string to wstring */
wstring s2ws(const std::string &str);
/* convert wstring to string */
string ws2s(const std::wstring &str);

string decodeText(std::string encodedText);
string encodeText(std::string decodedText);

string readTextFromScreen();
string readTextFromFile(char* fileName);

void displayToScreen(string text);
void writeToFile(string text, char* fileName);

void showOutput(int dest, string output);
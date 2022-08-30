// herders from cpp
#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* File stream*/
#include <fstream>
using std::ifstream;
using std::ofstream;

/* Set mode */
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include <chrono>
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;
using std::chrono::milliseconds;

// external header library
/* cryptp library */
#include <cryptopp/cryptlib.h>
/* string  Transformation*/
#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

/* file input, output*/
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

/* hex converted */
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
/* base64 converted */
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

// mode of operation
// #include "cryptopp/modes.h"

#include "ultilities.h"

// random number generation
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

// block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "ultilities.h"

/* convert string to wstring */
wstring s2ws(const std::string &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> tostring;
	return tostring.to_bytes(str);
}

string decodeText(std::string encodedText)
{
	string decoded;
	StringSource ss(encodedText, true, new HexDecoder(new StringSink(decoded)));

	return decoded;
}

string encodeText(std::string decodedText)
{
	string encoded;
	StringSource ss(decodedText, true, new HexEncoder(new StringSink(encoded)));

	return encoded;
}

string readTextFromScreen()
{
	wstring wText;
	wcin.ignore();
	std::getline(wcin, wText);
	return ws2s(wText);
}

string readTextFromFile(char *fileName)
{
	string text;
	CryptoPP::FileSource file(fileName, true, new StringSink(text));
	return text;
}

void displayToScreen(string text)
{
	wcout << s2ws(text) << endl;
}

void writeToFile(string text, char *fileName)
{
	CryptoPP::StringSource(text, true, new FileSink(fileName));
}

void showOutput(int dest, string output)
{
	// Print hash output in hex form
	switch (dest)
	{
	case 1:
		/* screen */
		{
			displayToScreen(output);
		}
		break;
	case 2:
		/* file */
		{
			writeToFile(output, (char *)"output.txt");
		}
		break;
	default:
		break;
	}
}

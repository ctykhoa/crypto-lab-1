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
#include "modeimplementations.h"

double encryptECB(string plain, CryptoPP::byte *key)
{
	double etime;
	string cipher;

	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, 32);

	auto start_s = high_resolution_clock::now();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
double decryptECB(string cipher, CryptoPP::byte *key)
{
	double etime;
	string plain;

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, 32);
	auto start_s = high_resolution_clock::now();
	// Execute

	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}

// CBC
double encryptCBC(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;

	CBC_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, 32, iv);

	auto start_s = high_resolution_clock::now();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
double decryptCBC(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;

	CBC_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, 32, iv);
	auto start_s = high_resolution_clock::now();
	// Execute

	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
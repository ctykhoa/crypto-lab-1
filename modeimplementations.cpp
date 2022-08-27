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

#include <cryptopp/xts.h>
using CryptoPP::XTS_Mode;

#include <cryptopp/ccm.h>
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::CCM;
using CryptoPP::Redirector;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

using CryptoPP::CCM_Base;

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

// OFB
double encryptOFB(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;

	OFB_Mode<AES>::Encryption e;
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
double decryptOFB(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;

	OFB_Mode<AES>::Decryption d;
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

// CFB
double encryptCFB(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;

	CFB_Mode<AES>::Encryption e;
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
double decryptCFB(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;

	CFB_Mode<AES>::Decryption d;
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

// CTR
double encryptCTR(string plain, CryptoPP::byte *key, CryptoPP::byte *ctr)
{
	double etime;
	string cipher;

	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, 32, ctr);

	auto start_s = high_resolution_clock::now();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
double decryptCTR(string cipher, CryptoPP::byte *key, CryptoPP::byte *ctr)
{
	double etime;
	string plain;

	CTR_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, 32, ctr);
	auto start_s = high_resolution_clock::now();
	// Execute

	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}

// XTS
double encryptXTS(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;

	XTS_Mode<AES>::Encryption e;
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
double decryptXTS(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;

	XTS_Mode<AES>::Decryption d;
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

// CCM
double encryptCCM(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;

	CCM<AES>::Encryption e;
	e.SetKeyWithIV(key, 32, iv, 13);
	e.SpecifyDataLengths(0, plain.size(), 0);

	// wcout << "MaxMessageLength(): " <<  CCM_Base::MaxMessageLength() << endl;
	auto start_s = high_resolution_clock::now();
	// Execute
	StringSource ss1(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
double decryptCCM(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;

	CCM<AES>::Decryption d;
	d.SetKeyWithIV(key, 32, iv, 13);
	d.SpecifyDataLengths(0, cipher.size() - 16, 0);

	auto start_s = high_resolution_clock::now();
	// Execute
	AuthenticatedDecryptionFilter df(d, new StringSink(plain));
	StringSource ss2(cipher, true, new Redirector(df)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}

// GCM
double encryptGCM(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string cipher;
	const int TAG_SIZE = 12;

	GCM<AES>::Encryption e;
	e.SetKeyWithIV(key, 32, iv, 13);

	// wcout << "MaxMessageLength(): " <<  GCM_Base::MaxMessageLength() << endl;
	auto start_s = high_resolution_clock::now();
	// Execute
	StringSource ss1(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher), false, TAG_SIZE)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
double decryptGCM(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
	double etime;
	string plain;
	const int TAG_SIZE = 12;

	GCM<AES>::Decryption d;
	d.SetKeyWithIV(key, 32, iv, 13);

	auto start_s = high_resolution_clock::now();
	// Execute
	AuthenticatedDecryptionFilter df(d, new StringSink(plain), 16 , TAG_SIZE);

	StringSource ss2(cipher, true, new Redirector(df)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	return etime;
}
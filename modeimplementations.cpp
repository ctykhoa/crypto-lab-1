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

double encryptECB(string plain, string inKey, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
		}
		break;
	default:
		break;
	}

	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, sizeof(key));

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptECB(string cipher, string inKey, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
		}
		break;
	default:
		break;
	}

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, sizeof(key));
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// CBC
double encryptCBC(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CBC_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptCBC(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CBC_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// OFB
double encryptOFB(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	OFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptOFB(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	OFB_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// CFB
double encryptCFB(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptCFB(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CFB_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// CTR
double encryptCTR(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptCTR(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CTR_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// XTS
double encryptXTS(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	XTS_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptXTS(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	XTS_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	StringSource ss3(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}

// CCM
double encryptCCM(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CCM<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
	e.SpecifyDataLengths(0, plain.size(), 0);

	// wcout << "MaxMessageLength(): " <<  CCM_Base::MaxMessageLength() << endl;
	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher))); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptCCM(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	CCM<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
	d.SpecifyDataLengths(0, cipher.size() - 16, 0);

	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	AuthenticatedDecryptionFilter df(d, new StringSink(plain));
	StringSource ss2(cipher, true, new Redirector(df)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, plain);
	}

	return etime;
}

// GCM
double encryptGCM(string plain, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string cipher, output;
	const int TAG_SIZE = 12;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	GCM<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	// wcout << "MaxMessageLength(): " <<  GCM_Base::MaxMessageLength() << endl;
	auto start_s = high_resolution_clock::now();
	cipher.clear();
	// Execute
	StringSource ss1(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher), false, TAG_SIZE)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	output = encodeText(cipher);
	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
double decryptGCM(string cipher, string inKey, string inIV, int inputSource, int isOutput, int outputDest)
{
	double etime;
	string plain, output;
	const int TAG_SIZE = 12;
	CryptoPP::byte key[32];
	CryptoPP::byte iv[12];

	switch (inputSource)
	{
	case 1:
		/* Random */
		{
			// random number generation
			AutoSeededRandomPool prng;
			// key generation
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	case 2:
		/* screen */
	case 3:
		/* file */
		{
			CryptoPP::StringSource(inKey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
			CryptoPP::StringSource(inIV, true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));
		}
		break;
	default:
		break;
	}

	GCM<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	auto start_s = high_resolution_clock::now();
	plain.clear();
	// Execute
	AuthenticatedDecryptionFilter df(d, new StringSink(plain), 16, TAG_SIZE);

	StringSource ss2(cipher, true, new Redirector(df)); // StringSource

	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
	duration<double, std::milli> etime_s = (stop_s - start_s);
	etime = etime_s.count();

	if (isOutput == 1)
	{
		showOutput(outputDest, output);
	}

	return etime;
}
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
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
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

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include <cryptopp/xts.h>
using CryptoPP::XTS_Mode;

#include <cryptopp/ccm.h>
using CryptoPP::CCM;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::SecByteBlock;

// ECB
double encryptECB(string plain, CryptoPP::byte * key);
double decryptECB(string cipher, CryptoPP::byte * key);

// CBC
double encryptCBC(string plain, CryptoPP::byte * key, CryptoPP::byte * iv);
double decryptCBC(string cipher, CryptoPP::byte * key, CryptoPP::byte * iv);

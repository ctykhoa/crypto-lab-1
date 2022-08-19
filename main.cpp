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

/* Set mode */
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

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
#include "cryptopp/modes.h"
// funtion definitions
/* convert string to wstring */
wstring s2ws(const std::string &str);
/* convert wstring to string */
string ws2s(const std::wstring &str);

string decodeText(std::string encodedText);
string encodeText(std::string decodedText);

// random number generation
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

// block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::SecByteBlock;

// ECB
void setRandomECBEncryptKey(ECB_Mode<AES>::Encryption &e);
void inputECBEncryptKeyFromScreen(ECB_Mode<AES>::Encryption &e);
void importECBEncryptKeyFromFile(ECB_Mode<AES>::Encryption &e);

void inputECBDecryptKeyFromScreen(ECB_Mode<AES>::Decryption &d);
void importECBDecryptKeyFromFile(ECB_Mode<AES>::Decryption &d);

// CBC
void setRandomCBCEncryptKey(CBC_Mode<AES>::Encryption &e);
void inputCBCEncryptKeyFromScreen(CBC_Mode<AES>::Encryption &e);
void importCBCEncryptKeyFromFile(CBC_Mode<AES>::Encryption &e);

void inputCBCDecryptKeyFromScreen(CBC_Mode<AES>::Decryption &d);
void importCBCDecryptKeyFromFile(CBC_Mode<AES>::Decryption &d);

// OFB
void setRandomOFBEncryptKey(OFB_Mode<AES>::Encryption &e);
void inputOFBEncryptKeyFromScreen(OFB_Mode<AES>::Encryption &e);
void importOFBEncryptKeyFromFile(OFB_Mode<AES>::Encryption &e);

void inputOFBDecryptKeyFromScreen(OFB_Mode<AES>::Decryption &d);
void importOFBDecryptKeyFromFile(OFB_Mode<AES>::Decryption &d);

// CFB
void setRandomCFBEncryptKey(CFB_Mode<AES>::Encryption &e);
void inputCFBEncryptKeyFromScreen(CFB_Mode<AES>::Encryption &e);
void importCFBEncryptKeyFromFile(CFB_Mode<AES>::Encryption &e);

void inputCFBDecryptKeyFromScreen(CFB_Mode<AES>::Decryption &d);
void importCFBDecryptKeyFromFile(CFB_Mode<AES>::Decryption &d);

// CTR
void setRandomCTREncryptKey(CTR_Mode<AES>::Encryption &e);
void inputCTREncryptKeyFromScreen(CTR_Mode<AES>::Encryption &e);
void importCTREncryptKeyFromFile(CTR_Mode<AES>::Encryption &e);

void inputCTRDecryptKeyFromScreen(CTR_Mode<AES>::Decryption &d);
void importCTRDecryptKeyFromFile(CTR_Mode<AES>::Decryption &d);

int main(int argc, char *argv[])
{
// #ifdef __linux__
// 	setlocale(LC_ALL, "");
// #elif _WIN32
// 	_setmode(_fileno(stdin), _O_U16TEXT);
// 	_setmode(_fileno(stdout), _O_U16TEXT);
// #else
// #endif

	// Read mode from screen
	int inputMode = 0, modeIndex = 0, inputMethod = 0, plainTextInput = 0, cipherTextInput = 0, inputAction = 0;
	string selection;
	ifstream modeSelection("modes.txt");
	string modes[10];

	wcout << "Select mode of operations:" << endl;
	while (getline(modeSelection, selection))
	{
		modes[modeIndex] = selection;
		wcout << s2ws(selection) << endl;
		modeIndex++;
	}

	wcin >> inputMode;
	while (inputMode < 1 || inputMode > modeIndex)
	{
		wcout << "Invalid selection! Please select another:" << endl;
		wcin >> inputMode;
	}

	wcout << "Encrypt/Decrypt:\n1.Encrypt\n2.Decrypt\n";
	wcin >> inputAction;

	wstring wplain, wcipher;
	string plain, cipher, encoded, recovered, inputKey, decoded;

	if (inputAction == 1) // Encrypt
	{
		wcout << "Secret key,  Initialization Vector IV, and nonce,.." << endl;
		wcout << "Case 1: Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool;\n Case 2: Input Secret Key and IV from screen\n Case 3: Input Secret Key and IV from file (using file name)\n";
		wcin >> inputMethod;

		wcout << "plain text: " << endl;
		cin.ignore();
		getline(wcin, wplain);

		switch (inputMode) // Mode of operations
		{
		case 1: // ECB Mode
		{
			ECB_Mode<AES>::Encryption e;

			switch (inputMethod) // How to input key
			{
			case 1: // random
			{
				setRandomECBEncryptKey(e);
			}
			break;
			case 2: // from screen
			{
				inputECBEncryptKeyFromScreen(e);
			}
			break;
			case 3: // from file
			{
				importECBEncryptKeyFromFile(e);
			}
			break;
			}

			StringSource ss1(ws2s(wplain), true, new StreamTransformationFilter(e, new StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING) // StreamTransformationFilter  ::PKCS_PADDING
			);

			// Pretty print cipher text
			encoded = encodeText(cipher);
			// StringSource ss2(cipher, true,
			// 				 new HexEncoder(
			// 					 new StringSink(encoded)) // HexEncoder

			// );

			wcout << "cipher text: " << s2ws(encoded) << endl;
		}
		break;

		case 2: // CBC
		{
			CBC_Mode<AES>::Encryption e;

			switch (inputMethod) // How to input key
			{
			case 1: // random
			{
				setRandomCBCEncryptKey(e);
			}
			break;
			case 2: // from screen
			{
				inputCBCEncryptKeyFromScreen(e);
			}
			break;
			case 3: // from file
			{
				importCBCEncryptKeyFromFile(e);
			}
			break;
			}

			StringSource ss1(ws2s(wplain), true, new StreamTransformationFilter(e, new StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING) // StreamTransformationFilter
			);

			// Pretty print cipher text
			encoded = encodeText(cipher);

			wcout << "cipher text: " << s2ws(encoded) << endl;
		}
		break;

		case 3: // OFB
		{
			OFB_Mode<AES>::Encryption e;

			switch (inputMethod) // How to input key
			{
			case 1: // random
			{
				setRandomOFBEncryptKey(e);
			}
			break;
			case 2: // from screen
			{
				inputOFBEncryptKeyFromScreen(e);
			}
			break;
			case 3: // from file
			{
				importOFBEncryptKeyFromFile(e);
			}
			break;
			}

			StringSource ss1(ws2s(wplain), true, new StreamTransformationFilter(e, new StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING) // StreamTransformationFilter
			);

			// Pretty print cipher text
			encoded = encodeText(cipher);

			wcout << "cipher text: " << s2ws(encoded) << endl;
		}
		break;

		case 4: // CFB
		{
			CFB_Mode<AES>::Encryption e;

			switch (inputMethod) // How to input key
			{
			case 1: // random
			{
				setRandomCFBEncryptKey(e);
			}
			break;
			case 2: // from screen
			{
				inputCFBEncryptKeyFromScreen(e);
			}
			break;
			case 3: // from file
			{
				importCFBEncryptKeyFromFile(e);
			}
			break;
			}

			StringSource ss1(ws2s(wplain), true, new StreamTransformationFilter(e, new StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING) // StreamTransformationFilter
			);

			// Pretty print cipher text
			encoded = encodeText(cipher);

			wcout << "cipher text: " << s2ws(encoded) << endl;
		}
		break;

		case 5: // CTR
		{
			CTR_Mode<AES>::Encryption e;

			switch (inputMethod) // How to input key
			{
			case 1: // random
			{
				setRandomCTREncryptKey(e);
			}
			break;
			case 2: // from screen
			{
				inputCTREncryptKeyFromScreen(e);
			}
			break;
			case 3: // from file
			{
				importCTREncryptKeyFromFile(e);
			}
			break;
			}

			StringSource ss1(ws2s(wplain), true, new StreamTransformationFilter(e, new StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING) // StreamTransformationFilter
			);

			// Pretty print cipher text
			encoded = encodeText(cipher);

			wcout << "cipher text: " << s2ws(encoded) << endl;
		}
		break;

		default:
			break;
		}
	}
	else if (inputAction == 2) // Decrypt
	{
		wcout << "Secret key,  Initialization Vector IV, and nonce,.." << endl;
		wcout << "Case 1: Input Secret Key and IV from screen\n Case 2: Input Secret Key and IV from file (using file name)\n";
		wcin >> inputMethod;

		wcout << "cipher text: " << endl;
		cin.ignore();
		getline(wcin, wcipher);

		switch (inputMode)
		{
		case 1: // ECB
		{
			ECB_Mode<AES>::Decryption d;

			switch (inputMethod) // How to input key
			{
			case 1: // from screen
			{
				inputECBDecryptKeyFromScreen(d);
			}
			break;
			case 2: // from file
			{
				importECBDecryptKeyFromFile(d);
			}
			break;
			}

			// The StreamTransformationFilter removes
			//  padding as required.

			try
			{
				wcout << "wcipher: " << wcipher << endl;

				// /* input hex string to output string*/
				// 	string outstring;
				// 	outstring.clear();
				// 	StringSource(ws2s(wcipher), true, new HexDecoder(new StringSink(outstring)));

				// 	StringSource ss3( outstring, true,
				// 	new StreamTransformationFilter( d,
				// 		new StringSink( recovered )
				// 	) // StreamTransformationFilter
				// ); // StringSource

				decoded = decodeText(ws2s(wcipher));
				// StringSource ss3(ws2s(wcipher), true, new HexDecoder(new StringSink(decoded)));

				CryptoPP::StringSource ss4(decoded, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered)));
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';
				system("pause");
			}

			wcout << "recovered text: " << s2ws(recovered) << endl;
			// /* write string to file StringSource- FileSink*/
			StringSource(recovered, true, new FileSink("base64out.txt"));
		}
		break;

		case 2: // CBC
		{
			CBC_Mode<AES>::Decryption d;

			switch (inputMethod) // How to input key
			{
			case 1: // from screen
			{
				inputCBCDecryptKeyFromScreen(d);
			}
			break;
			case 2: // from file
			{
				importCBCDecryptKeyFromFile(d);
			}
			break;
			}

			// The StreamTransformationFilter removes
			//  padding as required.

			try
			{
				wcout << "wcipher: " << wcipher << endl;

				decoded = decodeText(ws2s(wcipher));

				CryptoPP::StringSource ss4(decoded, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING));
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';

				StringSource(e.what(), true, new FileSink("base64out-err.txt"));
				system("pause");
			}

			wcout << "recovered text: " << s2ws(recovered) << endl;
			// /* write string to file StringSource- FileSink*/
			StringSource(recovered, true, new FileSink("base64out.txt"));
		}
		break;

		case 3: // OFB
		{
			OFB_Mode<AES>::Decryption d;

			switch (inputMethod) // How to input key
			{
			case 1: // from screen
			{
				inputOFBDecryptKeyFromScreen(d);
			}
			break;
			case 2: // from file
			{
				importOFBDecryptKeyFromFile(d);
			}
			break;
			}

			// The StreamTransformationFilter removes
			//  padding as required.

			try
			{
				wcout << "wcipher: " << wcipher << endl;

				decoded = decodeText(ws2s(wcipher));

				CryptoPP::StringSource ss4(decoded, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING));
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';

				StringSource(e.what(), true, new FileSink("base64out-err.txt"));
				system("pause");
			}

			wcout << "recovered text: " << s2ws(recovered) << endl;
			// /* write string to file StringSource- FileSink*/
			StringSource(recovered, true, new FileSink("base64out.txt"));
		}
		break;

		case 4: // CFB
		{
			CFB_Mode<AES>::Decryption d;

			switch (inputMethod) // How to input key
			{
			case 1: // from screen
			{
				inputCFBDecryptKeyFromScreen(d);
			}
			break;
			case 2: // from file
			{
				importCFBDecryptKeyFromFile(d);
			}
			break;
			}

			// The StreamTransformationFilter removes
			//  padding as required.

			try
			{
				wcout << "wcipher: " << wcipher << endl;

				decoded = decodeText(ws2s(wcipher));

				CryptoPP::StringSource ss4(decoded, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING));
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';

				StringSource(e.what(), true, new FileSink("base64out-err.txt"));
				system("pause");
			}

			wcout << "recovered text: " << s2ws(recovered) << endl;
			// /* write string to file StringSource- FileSink*/
			StringSource(recovered, true, new FileSink("base64out.txt"));
		}
		break;

		case 5: // CTR
		{
			CTR_Mode<AES>::Decryption d;

			switch (inputMethod) // How to input key
			{
			case 1: // from screen
			{
				inputCTRDecryptKeyFromScreen(d);
			}
			break;
			case 2: // from file
			{
				importCTRDecryptKeyFromFile(d);
			}
			break;
			}

			// The StreamTransformationFilter removes
			//  padding as required.

			try
			{
				wcout << "wcipher: " << wcipher << endl;

				decoded = decodeText(ws2s(wcipher));

				CryptoPP::StringSource ss4(decoded, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING));
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';

				StringSource(e.what(), true, new FileSink("base64out-err.txt"));
				system("pause");
			}

			wcout << "recovered text: " << s2ws(recovered) << endl;
			// /* write string to file StringSource- FileSink*/
			StringSource(recovered, true, new FileSink("base64out.txt"));
		}
		break;

		default:
			break;
		}
	}

	system("pause");
}

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

// ECB
void setRandomECBEncryptKey(ECB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	// random number generation
	AutoSeededRandomPool prng;

	// key generation
	prng.GenerateBlock(key, sizeof(key));

	e.SetKey(key, sizeof(key));
}

void inputECBEncryptKeyFromScreen(ECB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	/* input from screen */
	wstring winkey;
	string inkey;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);
	/* input a string to sub bytes StringSource--ArraySink */
	// ouput 8 bytes
	// convert wstring to string
	inkey = ws2s(winkey);
	StringSource(inkey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));

	wcout << "key: " << key << endl;

	e.SetKey(key, sizeof(key));
}

void importECBEncryptKeyFromFile(ECB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	FileSource fs("AES_key.key", false);
	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data from AES_key.key  to  key */
	fs.Detach(new Redirector(copykey));
	fs.Pump(sizeof(key)); // Pump first 32 bytes
	wcout << "key: " << key << endl;

	e.SetKey(key, sizeof(key));
}

void inputECBDecryptKeyFromScreen(ECB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];

	/* input from screen */
	wstring winkey;
	string inkey;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);
	/* input a string to sub bytes StringSource--ArraySink */
	// ouput 8 bytes
	// convert wstring to string
	inkey = ws2s(winkey);
	StringSource(inkey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	wcout << "key: " << key << endl;

	d.SetKey(key, sizeof(key));
}
void importECBDecryptKeyFromFile(ECB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];

	FileSource fs("AES_key.key", false);
	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data from AES_key.key  to  key */
	fs.Detach(new Redirector(copykey));
	fs.Pump(sizeof(key)); // Pump first 32 bytes
	wcout << "key: " << key << endl;

	d.SetKey(key, sizeof(key));
}

// CBC
void setRandomCBCEncryptKey(CBC_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	// random number generation
	AutoSeededRandomPool prng;

	// key generation
	prng.GenerateBlock(key, sizeof(key));

	byte iv[32];
	prng.GenerateBlock(iv, sizeof(iv));

	e.SetKeyWithIV(key, sizeof(key), iv);
}
void inputCBCEncryptKeyFromScreen(CBC_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	string inkey, iniv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */
	// ouput 8 bytes
	// convert wstring to string
	inkey = ws2s(winkey);

	StringSource(inkey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}
void importCBCEncryptKeyFromFile(CBC_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputCBCDecryptKeyFromScreen(CBC_Mode<AES>::Decryption &d)
{

	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	string inkey, iniv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */
	// ouput 8 bytes
	// convert wstring to string
	inkey = ws2s(winkey);
	StringSource(inkey, true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}
void importCBCDecryptKeyFromFile(CBC_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

// OFB
void setRandomOFBEncryptKey(OFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	// random number generation
	AutoSeededRandomPool prng;

	// key generation
	prng.GenerateBlock(key, sizeof(key));

	byte iv[32];
	prng.GenerateBlock(iv, sizeof(iv));

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputOFBEncryptKeyFromScreen(OFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void importOFBEncryptKeyFromFile(OFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputOFBDecryptKeyFromScreen(OFB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

void importOFBDecryptKeyFromFile(OFB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

// CFB
void setRandomCFBEncryptKey(CFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	// random number generation
	AutoSeededRandomPool prng;

	// key generation
	prng.GenerateBlock(key, sizeof(key));

	byte iv[32];
	prng.GenerateBlock(iv, sizeof(iv));

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputCFBEncryptKeyFromScreen(CFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void importCFBEncryptKeyFromFile(CFB_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputCFBDecryptKeyFromScreen(CFB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

void importCFBDecryptKeyFromFile(CFB_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

// CTR
void setRandomCTREncryptKey(CTR_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];

	// random number generation
	AutoSeededRandomPool prng;

	// key generation
	prng.GenerateBlock(key, sizeof(key));

	byte iv[32];
	prng.GenerateBlock(iv, sizeof(iv));

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputCTREncryptKeyFromScreen(CTR_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void importCTREncryptKeyFromFile(CTR_Mode<AES>::Encryption &e)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	e.SetKeyWithIV(key, sizeof(key), iv);
}

void inputCTRDecryptKeyFromScreen(CTR_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	/* input from screen */
	wstring winkey, winiv;
	wcout << "please input key:" << endl;
	std::getline(wcin, winkey);

	wcout << "please input IV:" << endl;
	std::getline(wcin, winiv);
	/* input a string to sub bytes StringSource--ArraySink */

	StringSource(ws2s(winkey), true, new CryptoPP::ArraySink(key, sizeof(key) - 1));
	StringSource(ws2s(winiv), true, new CryptoPP::ArraySink(iv, sizeof(iv) - 1));

	wcout << "key: " << key << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
}

void importCTRDecryptKeyFromFile(CTR_Mode<AES>::Decryption &d)
{
	CryptoPP::byte key[32];
	CryptoPP::byte iv[32];

	FileSource fskey("AES_key.key", false);
	FileSource fsiv("AES_IV.key", false);

	/*Create space  for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));

	/*Copy data from AES_key.key  to  key */
	fskey.Detach(new Redirector(copykey));
	fsiv.Detach(new Redirector(copyiv));

	fskey.Pump(sizeof(key)); // Pump first 32 bytes
	fsiv.Pump(sizeof(iv));	 // Pump first 32 bytes

	wcout << "key: " << key << endl;
	wcout << "iv: " << iv << endl;

	d.SetKeyWithIV(key, sizeof(key), iv);
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
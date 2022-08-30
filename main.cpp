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
#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;
// using CryptoPP::CFB_Mode;
// using CryptoPP::CTR_Mode;
// using CryptoPP::ECB_Mode;
// using CryptoPP::OFB_Mode;

#include <cryptopp/xts.h>
using CryptoPP::XTS_Mode;

#include <cryptopp/ccm.h>
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::CCM;
using CryptoPP::Redirector;

// using CCM_Base;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include "ultilities.h"
#include "modeimplementations.h"

// random number generation
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

// block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

int main(int argc, char *argv[])
{

#ifdef __linux__
	setlocale(LC_ALL, "");
#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

	int rounds = 0;
	wcout << "Number of round: " << endl;
	wcin >> rounds;
	if (rounds < 0)
	{
		wcout << "Invalid!" << endl;
		return 0;
	}
	int mode, function, inputSource, plainTextSource = 1, cipherTextSource = 1, outputDest;
	string inKey = "", iniv, plain, cipher, output, input;
	wstring wplain, wcipher;
	double total = 0;

	wcout << "Support modes: 1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM\n";
	wcin >> mode;
	wcout << "1.Encryption or 2.Decryption:\n";
	wcin >> function;
	if (function == 1)
	{
		wcout << "Secret key,  Initialization Vector IV, and nonce,..\nCase 1: Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool;\nCase 2: Input Secret Key and IV from screen\nCase 3: Input Secret Key and IV from file (using file name)\n";
		wcin >> inputSource;
	}
	else
	{
		wcout << "Secret key,  Initialization Vector IV, and nonce,..\nCase 1: Input Secret Key and IV from screen\nCase 2: Input Secret Key and IV from file (using file name)\n";
		wcin >> inputSource;
		if (inputSource == 1)
		{
			inputSource = 2; // from screen
		}
		else if (inputSource == 2)
		{
			inputSource = 3; // from file
		}
		else
		{
			inputSource = 4; // to throw error
		}
	}

	if (function == 1)
	{
		wcout << "Plain text: \nCase 1: Input from screen;\nCase 2: From files (using file name);\n";
		wcin >> plainTextSource;
	}
	else
	{
		wcout << "Ciphertext:\nCase 1: Input from screen;\nCase 2: From files (using file name);\n";
		wcin >> cipherTextSource;
	}
	wcout << "Ouputs: \n1.display in screen;\n2.write to file;\n";
	wcin >> outputDest;

	switch (inputSource)
	{
	case 1:
		/* Random */
		break;
	case 2:
		/* screen */
		{
			wcout << "Input key:\n";
			inKey = readTextFromScreen();
			if (mode != 1 /*ECB*/)
			{
				wcout << "Input IV:\n";
				iniv = readTextFromScreen();
			}
		}
		break;
	case 3:
		/* file */
		{
			inKey = readTextFromFile((char *)"AES_key.key");
			if (mode != 1 /*ECB*/)
			{
				iniv = readTextFromFile((char *)"AES_IV.key");
			}
		}
		break;
	default:
		break;
	}

	switch (function)
	{
	case 1:
		/* Encrypt */
		{
			switch (plainTextSource)
			{
			case 1:
				/* screen */
				{
					wcout << "Input plain text:\n";
					plain = readTextFromScreen();
				}
				break;
			case 2:
				/* file */
				{
					plain = readTextFromFile((char *)"plaintext_input.txt");
				}
				break;
			default:
				break;
			}
		}
		break;
	case 2:
		/* Decrypt */
		{
			switch (cipherTextSource)
			{
			case 1:
				/* screen */
				{

					wcout << "Input cipher text:\n";
					cipher = readTextFromScreen();
				}
				break;
			case 2:
				/* file */
				{
					cipher = readTextFromFile((char *)"ciphertext_input.txt");
				}
				break;
			default:
				break;
			}
		}
		break;

	default:
		break;
	}

	// Validate user input option:
	if ((mode < 1 || mode > 8) || (function != 1 && function != 2) || (inputSource < 1 || inputSource > 3) || (cipherTextSource < 1 || cipherTextSource > 2) || (outputDest != 1 && outputDest != 2))
	{
		wcout << "Invalid option!" << endl;
		system("pause");
		return 0;
	}

	switch (mode)
	{
	case 1:
		/* ECB */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptECB(plain, inKey, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptECB(plain, inKey, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptECB(decodedCipher, inKey, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptECB(decodedCipher, inKey, inputSource, 1, outputDest);
			}
		}
		break;
	case 2:
		/* CBC */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptCBC(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptCBC(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptCBC(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptCBC(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 3:
		/* OFB */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptOFB(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptOFB(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptOFB(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptOFB(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 4:
		/* CFB */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptCFB(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptCFB(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptCFB(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptCFB(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 5:
		/* CTR */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptCTR(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptCTR(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptCTR(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptCTR(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 6:
		/* XTS */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptXTS(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptXTS(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptXTS(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptXTS(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 7:
		/* CCM */
		{
			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptCCM(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptCCM(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptCCM(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptCCM(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	case 8:
		/* GCM */
		{
			const int TAG_SIZE = 12;

			if (function == 1)
			{
				// Encrypt
				int i = 1;
				input = plain;
				try
				{
					while (i <= rounds)
					{
						total = total + encryptGCM(plain, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				encryptGCM(plain, inKey, iniv, inputSource, 1, outputDest);
			}
			else
			{
				// Decrypt
				int i = 1;
				string decodedCipher;
				input = cipher;
				decodedCipher = decodeText(cipher);
				try
				{
					while (i <= rounds)
					{
						total = total + decryptGCM(decodedCipher, inKey, iniv, inputSource, 0, outputDest);
						i++;
					}
				}
				catch (const std::exception &e)
				{
					std::cerr << e.what() << '\n';
					system("pause");
				}

				decryptGCM(decodedCipher, inKey, iniv, inputSource, 1, outputDest);
			}
		}
		break;
	default:
		break;
	}

	wcout << "Input size: " << input.size() << " bytes" << endl;
	wcout << "Total time for " << rounds << " rounds: " << total << " ms" << endl;
	wcout << "Execution time: " << total / rounds << " ms" << endl;
	system("pause");
}
// time.cpp : Defines the entry point for the console application.
//g++ -o TimeSHA3-512.exe TimeSHA3-512.cpp -DNDEBUG -g2 -O3 -D_WIN32_WINNT=0x0501 -pthread ./lib/libcryptopp.a
#include <string>
#include <iostream>
using namespace std;
#include <chrono>
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;
// Include cryptopp header files
#include "cryptopp/sha3.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
using CryptoPP::SHA3_512;
using CryptoPP::byte;
double sha3(string input) {
	double etime;
	CryptoPP::SHA3_512 hash3;
	string in = input;
	CryptoPP::byte * buffer = (unsigned char*)malloc(in.size());
	CryptoPP::byte * out = (unsigned char*)malloc(hash3.DigestSize());
	// begin counting time of hashing the input
	auto start_s = high_resolution_clock::now(); 
	hash3.Restart(); // refresh output
	// compute ouput
	memcpy(buffer, in.data(), in.size());
	hash3.Update(buffer, in.size());
	hash3.Final(out); //finish compute hashing
	auto stop_s = high_resolution_clock::now();
	/* Getting number of milliseconds as a double. */
    duration<double, std::milli> etime_s = (stop_s-start_s);
	etime=etime_s.count();
	// Print hash output in hex form 
	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(out,64);
	encoder.MessageEnd();
	return etime;
}

int main (){
double result, total;
std::string input;
cout << "Please enter the input message: ";
getline(cin,input);
total=0;
int a=1;
while (a < 10001){
	total=total+sha3(input);
	a = a+1;
	}
result=total/10000; // running time
// recompute hash if needed
CryptoPP::SHA3_512 hash3;
CryptoPP::byte * buffer = (unsigned char*)malloc(input.size());
CryptoPP::byte * out = (unsigned char*)malloc(hash3.DigestSize());
hash3.Restart();
memcpy(buffer, input.data(), input.size());
hash3.Update(buffer, input.size());
hash3.Final(out);
CryptoPP::HexEncoder encoder;
std::string output;
encoder.Attach(new CryptoPP::StringSink(output));
encoder.Put(out,64);
encoder.MessageEnd();
std::string pause;
cout << "Input size: "<< input.size() << " bytes" << endl;
cout << "SHA3-512 output: " << output << endl;
cout << "Total time for 10.000 rounds: "<< total << " ms" << endl; 
cout << "Execution time: " << result << " ms"  << endl << endl;
cout << "Do you like to quite program?" << endl;
cin >> pause;
}


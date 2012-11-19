#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string>
#include <string.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <time.h>
#include <fstream>
#include <streambuf>
#include <iterator>
#include <termios.h>
#include <algorithm>
#include <bitset>

#include "cryptlib.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "sha.h"
#include "hex.h"
#include "base64.h"
#include "rsa.h"
#include "osrng.h"

using std::cout;
using std::cin;
using std::endl;

CryptoPP::RSA::PrivateKey ATMPrivateKey;
CryptoPP::RSA::PublicKey ATMPublicKey;
CryptoPP::RSA::PrivateKey BankPrivateKey;
CryptoPP::RSA::PublicKey BankPublicKey;

std::string SHA512HashString(const std::string& input)
{
    CryptoPP::SHA512 hash;
    byte digest[ CryptoPP::SHA512::DIGESTSIZE ];

    hash.CalculateDigest( digest, (byte*) input.c_str(), input.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    return output;
}

std::string toHex(std::string inputStr)
{
    std::string retStr = "";
    for(int i = 0; i < inputStr.length(); i++)
    {
        if(('0' <= inputStr[i] && inputStr[i] <= '9') || ('A' <= inputStr[i] && inputStr[i] <= 'F'))
        {
            retStr += inputStr[i];
        }
        else
        {
            retStr += "0";
        }
    }

    return retStr;
}

std::string toNumbers(std::string inputStr)
{
    std::string retStr = "";
    for(int i = 0; i < inputStr.length(); i++)
    {
        if('0' <= inputStr[i] && inputStr[i] <= '9')
        {
            retStr += inputStr[i];
        }
        else
        {
            retStr += "0";
        }
    }

    return retStr;
}

std::string toAlpha(std::string inputStr)
{
    std::string retStr = "";
    for(int i = 0; i < inputStr.length(); i++)
    {
        if('a' <= inputStr[i] && inputStr[i] <= 'z')
        {
            retStr += inputStr[i];
        }
    }

    return retStr;
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) 
{
	std::stringstream ss(s+' ');
	std::string item;
	while(std::getline(ss, item, delim)) 
	{
		if(item != "")
		{
			elems.push_back(item);   
		}
	}
	return elems;
}

std::string getRandom(int length)
{   
	std::string retStr = "";
	int num = 0;
    bool hex = true;
	for(unsigned int i = 0; i < length; ++i)
	{
        if(hex)
        {
            // Generate Random Hex String
    		num = (int) (rand() % 16);
    		if(num < 10)
    		{
    			retStr += (num + '0');
    		}
    		else
    		{
    			retStr += ((num - 10) + 'A');
    		}
        }
        else
        {
            // Generate Random String With ASCII Range (33, 126)
            num = (int) (rand() % (126 - 48));
            retStr += (num + '0');
        }
	}

	return retStr;
}

void* formPacket(char packet[], int packetLength , std::vector<std::string> &items)
{
    char delim = ',';
    packet[0] = '\0';
    int len = 0;
    std::string item = "";
    std::string packetData = "";
    
    for(int i = 0; i < items.size(); i++)
    {
        item = items[i];
        packetData += item;
        packetData += ","; 
        for(unsigned int j = 0; j < item.length(); ++j)
        {
            packet[len + j] = item[j];  //add username to packet
        }
        
        len += item.length();
        packet[len] = delim;
        len++;
    }

    // Adding Random Padding
    std::string randomString = getRandom(packetLength - 128 - 1 - len);
    for(unsigned int i = 0; i < randomString.length(); ++i)
    {
        packet[len + i] = randomString[i];
    }
    len += randomString.length();
    packet[len] = delim;
    len++;

    // Adding SHA-512 Hash
    std::string hashString = SHA512HashString((std::string) packetData + randomString);    
    for(unsigned int i = 0; i < hashString.length(); ++i)
    {
        packet[len + i] = hashString[i];
    }

    packet[packetLength] = '\0';
}

std::string encryptAESPacket(std::string plaintext, std::string AESKey, std::string AESBlock)
{
    byte key[ CryptoPP::AES::MAX_KEYLENGTH], iv[ CryptoPP::AES::BLOCKSIZE ];
    
    std::vector<char> bytes1(AESKey.begin(), AESKey.end());
    for(int i = 0; i < bytes1.size(); i++)
    {
        key[i] = bytes1[i];
    }
    
    std::vector<char> bytes2(AESBlock.begin(), AESBlock.end());
    for(int i = 0; i < bytes2.size(); i++)
    {
        iv[i] = bytes2[i];
    }

    std::string ciphertext;
    std::string encodedCiphertext;
    
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    CryptoPP::StringSource foo(ciphertext, true, new CryptoPP::Base64Encoder (new CryptoPP::StringSink(encodedCiphertext)));
    
    return encodedCiphertext;
}

std::string decryptAESPacket(std::string encodedCiphertext, std::string AESKey, std::string AESBlock)
{
    byte key[ CryptoPP::AES::MAX_KEYLENGTH], iv[ CryptoPP::AES::BLOCKSIZE ];
    
    std::vector<char> bytes1(AESKey.begin(), AESKey.end());
    for(int i = 0; i < bytes1.size(); i++)
    {
        key[i] = bytes1[i];
    }
    
    std::vector<char> bytes2(AESBlock.begin(), AESBlock.end());
    for(int i = 0; i < bytes2.size(); i++)
    {
        iv[i] = bytes2[i];
    }
    
    std::string ciphertext;
    std::string decryptedtext;

    CryptoPP::StringSource foo(encodedCiphertext, true, new CryptoPP::Base64Decoder (new CryptoPP::StringSink(ciphertext)));
   
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

    return decryptedtext;
}

void* generateRSAKeys()
{
    CryptoPP::AutoSeededRandomPool rng;

    cout << "Generating ATM Keys...." << endl;
    CryptoPP::InvertibleRSAFunction params1;
    params1.GenerateRandomWithKeySize(rng, 3072); // 256-char blocked messages
    CryptoPP::RSA::PrivateKey tempPrivateKey1(params1);
    ATMPrivateKey = tempPrivateKey1;
    CryptoPP::RSA::PublicKey tempPublicKey1(params1);
    ATMPublicKey = tempPublicKey1;


    cout << "Generating Bank Keys...." << endl;
    CryptoPP::InvertibleRSAFunction params2;
    params2.GenerateRandomWithKeySize(rng, 3072);
    CryptoPP::RSA::PrivateKey tempPrivateKey2(params2);
    BankPrivateKey = tempPrivateKey2;
    CryptoPP::RSA::PublicKey tempPublicKey2(params2);
    BankPublicKey = tempPublicKey2;
}

std::string encryptRSAATM(std::string plaintext)
{
    CryptoPP::AutoSeededRandomPool rng;
    std::string plain, cipher, encodedCiphertext, returnVal;
    int blockLength = 256;
    for(int i = 0; i < ((int) plaintext.length() / ((double) blockLength)); i++)
    {
        plain = "";
        cipher = "";
        encodedCiphertext = "";

        plain = plaintext.substr(i * blockLength, blockLength);

        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptBank(BankPublicKey);

        CryptoPP::StringSource ss1(plain, true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptBank,
                new CryptoPP::StringSink(cipher)
           ) // PK_EncryptorFilter
        ); // StringSource


        CryptoPP::StringSource foo1(cipher, true, new CryptoPP::Base64Encoder (new CryptoPP::StringSink(encodedCiphertext)));
        returnVal += encodedCiphertext;
        if(i != ((int) plaintext.length() / ((double) blockLength)) - 1)
            returnVal += ((std::string) ",");
    }

    return returnVal;
}

std::string decryptRSAATM(std::string ciphertext)
{
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<std::string> cipherArray = split(ciphertext, ',', cipherArray);
    std::string recovered, encodedCiphertext, decodedCiphertext, returnVal;
    
    for(int i = 0; i < cipherArray.size(); i++)
    {
        recovered = "";
        encodedCiphertext = "";
        decodedCiphertext = "";

        encodedCiphertext = cipherArray[i];
        cout << encodedCiphertext << endl << endl;
        CryptoPP::StringSource foo4(encodedCiphertext, true, new CryptoPP::Base64Decoder (new CryptoPP::StringSink(decodedCiphertext)));

        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptBank(BankPrivateKey);

        CryptoPP::StringSource ss2(decodedCiphertext, true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptBank,
                new CryptoPP::StringSink(recovered)
           ) // PK_DecryptorFilter
        ); // StringSource

        returnVal += recovered;
    }

    return returnVal;
}
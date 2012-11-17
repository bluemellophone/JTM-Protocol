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

using std::cout;
using std::cin;
using std::endl;

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
    std::string decodedCiphertext;
    
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    CryptoPP::StringSource foo(ciphertext, true, new CryptoPP::Base64Encoder (new CryptoPP::StringSink(decodedCiphertext)));
    
    return decodedCiphertext;
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
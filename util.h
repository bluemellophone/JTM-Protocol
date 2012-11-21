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
#include "files.h"

using std::cout;
using std::cin;
using std::endl;

std::string SHA512HashString(std::string input)
{
    std::string output;
    CryptoPP::SHA512 hash;
    byte digest[ CryptoPP::SHA512::DIGESTSIZE ];

    hash.CalculateDigest( digest, (byte*) input.c_str(), input.length() );

    CryptoPP::HexEncoder encoder;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    return output;
}

bool compareSHA512Hash(std::string receivedHash, std::string calculateHash)
{
    while(receivedHash.length() > 128)
    {
        receivedHash = receivedHash.substr(0, receivedHash.length() - 1);
    }
    calculateHash = SHA512HashString(calculateHash);

    return receivedHash == calculateHash;
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

bool isNumbersOnly(std::string inputStr)
{
    std::string retStr = "";
    for(int i = 0; i < inputStr.length(); i++)
    {
        if(!('0' <= inputStr[i] && inputStr[i] <= '9'))
        {
            return false;
        }
    }

    return true;
}

std::string getCardHash(std::string cardFile) 
{
    std::ifstream card(cardFile.c_str());
    std::string tempHash((std::istreambuf_iterator<char>(card)),std::istreambuf_iterator<char>());
    
    std::string cardHash = tempHash;
    cardHash = cardHash.substr(0,128);
    std::transform(cardHash.begin(), cardHash.end(), cardHash.begin(), ::toupper);
    cardHash = toHex(cardHash);
    
    return cardHash;
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
    CryptoPP::AutoSeededRandomPool rng;
    int random;
	int num = 0;
    bool hex = true;

	for(unsigned int i = 0; i < length; ++i)
	{
        random = (int) rng.GenerateByte();
        if(hex)
        {
            // Generate Random Hex String
    		num = (int) (random % 16);
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
            // Generate Random String With ASCII Range (48, 126)
            num = (int) (random % (126 - 48));
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
        packetData += item + ","; 
        for(unsigned int j = 0; j < item.length(); ++j)
        {
            packet[len + j] = item[j];
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

void* Save(const std::string& filename, const CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void* SavePrivateKey(const std::string& filename, const CryptoPP::RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void* SavePublicKey(const std::string& filename, const CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const std::string& filename, CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}

void LoadPrivateKey(const std::string& filename, CryptoPP::RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}

void* generateRSAKeys()
{
    CryptoPP::AutoSeededRandomPool rng;

    cout << "Generating ATM Keys...." << endl;
    CryptoPP::InvertibleRSAFunction params1;
    params1.GenerateRandomWithKeySize(rng, 6144); // 512-char blocked messages
    CryptoPP::RSA::PrivateKey tempPrivateKey1(params1);
    SavePrivateKey("keys/atm", tempPrivateKey1);
    CryptoPP::RSA::PublicKey tempPublicKey1(params1);
    SavePublicKey("keys/atm.pub", tempPublicKey1);


    cout << "Generating Bank Keys...." << endl;
    CryptoPP::InvertibleRSAFunction params2;
    params2.GenerateRandomWithKeySize(rng, 6144); // 512-char blocked messages
    CryptoPP::RSA::PrivateKey tempPrivateKey2(params2);
    SavePrivateKey("keys/bank", tempPrivateKey2);
    CryptoPP::RSA::PublicKey tempPublicKey2(params2);
    SavePublicKey("keys/bank.pub", tempPublicKey2);

}

std::string encryptRSAPacket(std::string plaintext, std::string keyFile)
{
    std::string ciphertext, encodedCiphertext;
    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::RSA::PublicKey publicKey;
    LoadPublicKey(keyFile, publicKey);
    CryptoPP::RSAES_OAEP_SHA_Encryptor encrypt(publicKey);    

    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::PK_EncryptorFilter(rng, encrypt,
            new CryptoPP::StringSink(ciphertext)
       ) // PK_EncryptorFilter
    ); // StringSource

    CryptoPP::StringSource foo1(ciphertext, true, new CryptoPP::Base64Encoder (new CryptoPP::StringSink(encodedCiphertext)));
    
    return encodedCiphertext;
}

std::string decryptRSAPacket(std::string encodedCiphertext, std::string keyFile)
{
    std::string ciphertext, plaintext;
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey privateKey;
    LoadPrivateKey(keyFile, privateKey);
    CryptoPP::RSAES_OAEP_SHA_Decryptor decrypt(privateKey);

    CryptoPP::StringSource foo4(encodedCiphertext, true, new CryptoPP::Base64Decoder (new CryptoPP::StringSink(ciphertext)));

    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::PK_DecryptorFilter(rng, decrypt,
            new CryptoPP::StringSink(plaintext)
       ) // PK_DecryptorFilter
    ); // StringSource

    return plaintext;
}

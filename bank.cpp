/**
  @file bank.cpp
  @brief Top level bank implementation file
 */

#include "account.h"

void* client_thread(void* arg);
void* console_thread(void* arg);

void* formBankHandshake(char packet[], std::string command, std::string atmNonce, std::string bankNonce, std::string AESKey, std::string AESSession)
{
    std::vector<std::string> tempVector;
    tempVector.push_back(command);
    tempVector.push_back(atmNonce);
    tempVector.push_back(bankNonce);
    tempVector.push_back(AESKey);
    tempVector.push_back(AESSession);
    formPacket(packet, 512, tempVector);
}

void* formBankPacket(char packet[], std::string command, std::string status, std::string atmNonce, std::string bankNonce)
{
    std::vector<std::string> tempVector;
    tempVector.push_back(command);
    tempVector.push_back(status);
    tempVector.push_back(atmNonce);
    tempVector.push_back(bankNonce);
    formPacket(packet, 1023, tempVector);
}

bool login (std::vector<std::string> info) 
{
	std::vector<Account>::iterator it;
	int pin = atoi(info.at(3).c_str());

	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_pin() == pin && !it->get_logged_in()) {
			it->set_logged_in_true ();
			return true;
		} 
	}
	return false;
}

float checkBalance (std::vector<std::string> info)
{
	std::vector<Account>::iterator it;

	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_logged_in()) {
			return it->get_balance();
		}
	}
	return -1;
}

bool processWithdraw (std::vector<std::string> info)
{
	float b = (float)atof(info.at(4).c_str());
	if (b > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance() && it->get_withdraw() + b <= 1000.00) {
			it->reduce_balance(b);
			it->increase_withdraw (b);
			return true;
		}
	}
	return false;
}

bool processTransfer (std::vector<std::string> info)
{
	float b = (float)atof(info.at(4).c_str());
	if (b > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance() && it->get_transfer() + b <= 1000.00) {
			it->reduce_balance(b);
			it->increase_transfer (b);
			std::vector<Account>::iterator foo;
			for (foo = Database.begin(); foo != Database.end(); foo++) {
				if (foo->get_un() == info.at(5)) {
					foo->increase_balance (b);
					return true;
				}
			}
		}
	}
	return false;
}

bool processDeposit (std::string name, std::string amount)
{
	float a = (float)atof(amount.c_str());
	if (a > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == name && it->get_deposit() + a <= 1000.00) {
			it->increase_deposit(a);
			it->increase_balance(a);
			return true;
		}
	}
	return false;
}

float bankBalance (std::string name)
{
	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == name) {
			return it->get_balance();
		}
	}
	return -1;
}

bool logout (std::vector<std::string> info) 
{
	std::vector<Account>::iterator it;

	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_logged_in()) {
			it->set_logged_in_false();
			return true;
		}
	}
	return false;
}

int main(int argc, char* argv[])
{
    //generateRSAKeys();

	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}

	unsigned short ourport = atoi(argv[1]);

	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}

	//listening address
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}

	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);

	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;

		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)csock);
	}
}

void* client_thread(void* arg)
{
	//int csock = (int)arg;
	long unsigned int csock = (long unsigned int)arg;

	//input loop
	int length;
	bool valid;
	char packet[1024];
	char epacket[1408];
	std::vector<std::string> bufArray;

    std::string sessionAESKey;
    std::string sessionAESBlock;
	
	std::string bankNonce;
	std::string command;
	std::string status;

	std::string recievedHash;
	std::string recievedHashedData;
	std::string calculatedHash;
	std::string encryptedPacket;
	std::string decryptedPacket;
	std::string decryptedHandshake;
	std::string encryptedRSA;

	while(1)
	{
		valid = false;
		packet[0] = '\0';	
        epacket[0] = '\0';
		bufArray.clear();
		recievedHash = "";
		recievedHashedData = "";
		calculatedHash = "";
		status = "";

		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
		{
			break;
		}	
		if(length > 1408)
		{
			printf("[bank] packet too long\n");
			break;
		}
		if(length != recv(csock, epacket, length, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}
		else if(length == 1039)
		{	
        	epacket[1039] = '\0';
			//printf("[bank] Recieved Encrypted ATM Handshake (Length %d): \n%s\n\n", (int) ((std::string) epacket).length(), epacket);
			
            decryptedHandshake = decryptRSAPacket((std::string) epacket, "keys/bank");
            //cout << "[atm] Recieved ATM Handshake (Length " << decryptedHandshake.length() << "): " << endl << decryptedHandshake << endl << endl;
			
			bufArray = split(decryptedHandshake, ',', bufArray);
			
			if(bufArray.size() == 4)
			{
				recievedHash = bufArray[3];
				recievedHash = recievedHash.substr(0, recievedHash.length() - 1);
				recievedHashedData = bufArray[0] + "," + bufArray[1] + "," + bufArray[2];
				calculatedHash = SHA512HashString(recievedHashedData);

				//cout << recievedHash << " (Length " << recievedHash.length() << ")" << endl;
				//cout << calculatedHash << " (Length " << calculatedHash.length() << ")" << endl;
				if(recievedHash == calculatedHash)
				{
					command = bufArray[0];
						
					if(((std::string) "handshake") == command) //if command is 'login'
					{   
						bankNonce = getRandom(32);
						sessionAESKey = getRandom(32);
						sessionAESBlock = getRandom(16);

						formBankHandshake(epacket, "handshake", bufArray[1], bankNonce, sessionAESKey, sessionAESBlock);
					} 
					else
					{
						formBankHandshake(epacket, "error", bufArray[1], bankNonce, "00000000000000000000000000000000", "0000000000000000");
					}
				}
				else
				{
					formBankHandshake(epacket, "error", bufArray[1], bankNonce, "00000000000000000000000000000000", "0000000000000000");
				}
			} 
			else
			{
				// Error: Command sent from ATM not recognized.
				formBankHandshake(epacket, "error", bufArray[1], bankNonce, "00000000000000000000000000000000", "0000000000000000");
			}

			//cout << "[bank] Sending Bank Handshake (Length " << strlen(epacket) << "): " << endl << (std::string) epacket << endl << endl;
		    
		    encryptedRSA = encryptRSAPacket((std::string) epacket, "keys/atm.pub");
            
            for(int i = 0; i < encryptedRSA.length(); i++)
            {
                epacket[i] = encryptedRSA[i];
            }

            length = strlen(epacket);

			//cout << "[atm] Sending Encrypted Handshake (Length " << strlen(epacket) << "): " << endl << ((std::string) epacket) << endl << endl;
			//send the new packet back to the client
			if(sizeof(int) != send(csock, &length, sizeof(int), 0))
			{
				printf("[bank] fail to send packet length\n");
				break;
			}
			if(length != send(csock, (void*)epacket, length, 0))
			{
				printf("[bank] fail to send packet\n");
				break;
			}
		}	
		else if(length == 1408)
		{
			// RECIEVED AES PACKET

			//printf("[bank] Recieved ATM Encrypted Packet (Length %d): \n%s\n", (int) ((std::string) epacket).length(), epacket);
			decryptedPacket = decryptAESPacket((std::string) epacket, sessionAESKey, sessionAESBlock);
			//cout << "[bank] Recieved ATM Packet (Length " << decryptedPacket.length() << "): " << endl << decryptedPacket << endl << endl;

			for(int i = 0; i < decryptedPacket.length(); i++)
            {
                packet[i] = decryptedPacket[i];
            }

			bufArray = split((std::string) packet, ',', bufArray);
			packet[0] = '\0';

			if(bufArray.size() == 10)
			{
				recievedHash = bufArray[9];
				recievedHash = recievedHash.substr(0, recievedHash.length() - 1);
				recievedHashedData = bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4] + "," + bufArray[5] + "," + bufArray[6] + "," + bufArray[7] + "," + bufArray[8];
				calculatedHash = SHA512HashString(recievedHashedData);

				//cout << recievedHash << " (Length " << recievedHash.length() << ")" << endl;
				//cout << calculatedHash << " (Length " << calculatedHash.length() << ")" << endl;
				if(recievedHash == calculatedHash)
				{
					if(bankNonce == bufArray[7])
					{
						command = bufArray[0];
						bankNonce = getRandom(32);

						if(((std::string) "login") == command) //if command is 'login'
						{   
							bool flag = login (bufArray);
							if(flag) 
							{
								valid = true;
								status = "Login Successful";
							}
						} 
						else if(((std::string) "balance") == command) //if command is 'balance'
						{   
							float flag = checkBalance (bufArray);
							if (flag >= 0) 
							{
								valid = true;
								std::stringstream ss;
								ss << flag;
								std::string balance = ss.str();
								status = "Balance: $" + balance;
							}
						} 
						else if(((std::string) "withdraw") == command) //if command is 'withdraw'
						{   
							bool flag = processWithdraw (bufArray);
							if (flag) 
							{
								valid = true;
								status = "Withdraw: $" + bufArray[4];
							}
						}
						else if(((std::string) "transfer") == command) //if command is 'transfer'
						{   
							bool flag = processTransfer (bufArray);
							if (flag) 
							{
								valid = true;
								status = "Transfer Successful";
							}
						}  
						else if(((std::string) "logout") == command) //if command is 'logout'
						{   
							bool flag = logout (bufArray);
							if (flag)
							{
								valid = true;
								status = "Logout Successful";
							}
						}
					}
				}
			} 

			if(valid)
			{
				formBankPacket(packet, command, status, bufArray[6], bankNonce);
			}
			else
			{	
				if(((std::string) "login") == command)
				{
					formBankPacket(packet, "error", "User Login Failed.", bufArray[6], bankNonce);

				}
				else
				{
					formBankPacket(packet, "error", "Error.  Please contact the service team.", bufArray[6], bankNonce);
				}
			}

	        epacket[0] = '\0';
			
			//cout << "[bank] Sending Bank Packet (Length " << strlen(packet) << "): " << endl << (std::string) packet << endl << endl;
		    encryptedPacket = encryptAESPacket((std::string) packet, sessionAESKey, sessionAESBlock);
	        //cout << "[bank] Sending Bank Encrypted Packet (Length " << encryptedPacket.length() << "): " << endl << encryptedPacket << endl << endl;

	        for(int i = 0; i < encryptedPacket.length(); i++)
	        {
	            epacket[i] = encryptedPacket[i];
	        }

	        length = encryptedPacket.length();

			//send the new packet back to the client
			if(sizeof(int) != send(csock, &length, sizeof(int), 0))
			{
				printf("[bank] fail to send packet length\n");
				break;
			}
			if(length != send(csock, (void*)epacket, length, 0))
			{
				printf("[bank] fail to send packet\n");
				break;
			}
		}
		else
		{
			printf("[bank] ATM Packet configured incorrectly.\n");
		}
	}

	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80]; 
	std::string command;
	std::vector<std::string> bufArray;
	while(1)
	{
		bufArray.clear();

		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline

		// Parse data
		bufArray = split((std::string) buf, ' ', bufArray);

		//input parsing
		if(bufArray.size() >= 1 && ((std::string) "") != bufArray[0])
		{
			command = bufArray[0];

			if(((std::string) "deposit") == command) //if command is 'deposit'
			{   
				if(bufArray.size() == 3)
				{
					bool flag = processDeposit (bufArray[1], bufArray[2]);
					if (flag) {
						std::cout << "Deposit [ " << bufArray[1] << " ]: $ " << bufArray[2] << "\n";
					}
					else {
						std::cout << "Invalid deposit operation\n";
					}
				}
				else
				{
					std::cout << "Usage: deposit [username] [amount]\n";
				}
			} 
			else if(((std::string) "balance") == command) //if command is 'balance'
			{    
				if(bufArray.size() == 2)
				{
					float flag = bankBalance (bufArray[1]);
					if (flag >= 0) {
						std::cout << "Balance [ " << bufArray[1] << " ]: $ " << flag << "\n";
					}
					else {
						std::cout << "Invalid balance operation\n";
					}
				}
				else
				{
					std::cout << "Usage: balance [username]\n";
				}
			} 
			else
			{
				std::cout << "Command '" << command << "' not recognized.\n";
			}
		}
		else
		{
			std::cout << "Usage: [command] [argument...]\n";
		} 

	}
}

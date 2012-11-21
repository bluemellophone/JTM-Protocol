/**
  @file bank.cpp
  @brief Top level bank implementation file
 */

#include "account.h"

void* client_thread(void* arg);
void* console_thread(void* arg);

const static float MAX_BAL = 2000000000;

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
		if(it->get_un() == info.at(1) && it->get_pin() == pin && !it->get_logged_in() && !it->get_locked()) {
			it->set_logged_in_true ();
			return true;
		} 
		else if(it->get_un() == info.at(1) && it->get_pin() != pin && !it->get_logged_in()) {
			it->increase_login_attempts();
			if(it->get_login_attempts() >= 3) {
				it->lock();
			}
			return false;
		}
	}
	return false;
}

float checkBalance (std::vector<std::string> info)
{
	std::vector<Account>::iterator it;

	for (it = Database.begin(); it != Database.end(); it++) {
		if(it->get_un() == info.at(1) && it->get_logged_in()) {
			return it->get_balance();
		}
	}
	return -1;
}

bool processWithdraw (std::vector<std::string> info)
{
	float b = (float)atof(info.at(4).c_str());
	if(b > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if(it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance() && it->get_withdraw() + b <= 1000.00) {
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
	if(b > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if(it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance() && it->get_transfer() + b <= 1000.00) {
			it->reduce_balance(b);
			it->increase_transfer (b);
			std::vector<Account>::iterator foo;
			for (foo = Database.begin(); foo != Database.end(); foo++) {
				if(foo->get_un() == info.at(5) && foo->get_balance() + b <= MAX_BAL) {
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
	if(a > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if(it->get_un() == name && it->get_deposit() + a <= 1000.00 && it->get_balance() + a <= MAX_BAL) {
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
		if(it->get_un() == name) {
			return it->get_balance();
		}
	}
	return -1;
}

bool logout (std::vector<std::string> info) 
{
	std::vector<Account>::iterator it;

	for (it = Database.begin(); it != Database.end(); it++) {
		if(it->get_un() == info.at(1) && it->get_logged_in()) {
			it->set_logged_in_false();
			return true;
		}
	}
	return false;
}

int main(int argc, char* argv[])
{
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
	char packet[1024];
	char epacket[1408];
	std::vector<std::string> bufArray;

	std::string command;
	std::string status;
	std::string atmNonce;
	std::string bankNonce;

    std::string sessionAESKey;
    std::string sessionAESBlock;
	std::string encryptedPacket;
	std::string decryptedPacket;

	int length;
	bool sendPacket;

	while(1)
	{
		sendPacket = false;
		packet[0] = '\0';	
        epacket[0] = '\0';
        command = "";
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
			bankNonce = getRandom(32);
			command = "error";
			sessionAESKey = "NOT USED";
			sessionAESBlock = "NOT USED";
			epacket[1039] = '\0';
                    
			decryptedPacket = decryptRSAPacket((std::string) epacket, "keys/bank");
            bufArray.clear();
			bufArray = split(decryptedPacket, ',', bufArray);
			
			if(bufArray.size() == 4)
			{
				if(compareSHA512Hash(bufArray[3], bufArray[0] + "," + bufArray[1] + "," + bufArray[2]))
                {
					command = bufArray[0];
						
					if(((std::string) "handshake") == command)
					{   
						atmNonce = bufArray[1];
						sessionAESKey = getRandom(32);
						sessionAESBlock = getRandom(16);
					} 
				}
			} 

			formBankHandshake(epacket, command, atmNonce, bankNonce, sessionAESKey, sessionAESBlock);
		    encryptedPacket = encryptRSAPacket((std::string) epacket, "keys/atm.pub");
            
            for(int i = 0; i < encryptedPacket.length(); i++)
            {
                epacket[i] = encryptedPacket[i];
            }

            length = strlen(epacket);
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
			packet[0] = '\0';
			decryptedPacket = decryptAESPacket((std::string) epacket, sessionAESKey, sessionAESBlock);
			
			bufArray.clear();
			bufArray = split((std::string) decryptedPacket, ',', bufArray);

			if(bufArray.size() == 10)
			{
				if(compareSHA512Hash(bufArray[9], bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4] + "," + bufArray[5] + "," + bufArray[6] + "," + bufArray[7] + "," + bufArray[8]))
                {
					if(bankNonce == bufArray[7])
					{
						command = bufArray[0];
						atmNonce = bufArray[6];
						bankNonce = getRandom(32);

						if(((std::string) "login") == command)
						{   
							if(login(bufArray)) 
							{
								sendPacket = true;
								status = "Login Successful";
							}
						} 
						else if(((std::string) "balance") == command)
						{   
							float flag = checkBalance(bufArray);
							if(flag >= 0) 
							{
								sendPacket = true;
								std::stringstream ss;
								ss << flag;
								std::string balance = ss.str();
								status = "Balance: $" + balance;
							}
						} 
						else if(((std::string) "withdraw") == command)
						{   
							if(processWithdraw(bufArray)) 
							{
								sendPacket = true;
								status = "Withdraw: $" + bufArray[4];
							}
						}
						else if(((std::string) "transfer") == command)
						{   
							if(processTransfer(bufArray)) 
							{
								sendPacket = true;
								status = "Transfer Successful";
							}
						}  
						else if(((std::string) "logout") == command)
						{   
							if(logout (bufArray))
							{
								sendPacket = true;
								status = "Logout Successful";
							}
						}
					}
				}
			} 

			if(sendPacket)
			{
				formBankPacket(packet, command, status, atmNonce, bankNonce);
			}
			else
			{	
				if(((std::string) "login") == command)
				{
					formBankPacket(packet, "error", "User Login Failed.", atmNonce, bankNonce);
				}
				else
				{
					formBankPacket(packet, "error", "Error.  Please contact the service team.", atmNonce, bankNonce);
				}
			}

	        epacket[0] = '\0';
			encryptedPacket = encryptAESPacket((std::string) packet, sessionAESKey, sessionAESBlock);
	        
	        for(int i = 0; i < encryptedPacket.length(); i++)
	        {
	            epacket[i] = encryptedPacket[i];
	        }
	        epacket[1408] = '\0';

			length =  strlen(epacket);
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
	char buf[50]; 
	std::string command;
	std::vector<std::string> bufArray;
	while(1)
	{
		printf("bank> ");
		fgets(buf, 49, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline

		// Parse data
		bufArray.clear();
		bufArray = split((std::string) buf, ' ', bufArray);

		//input parsing
		if(bufArray.size() >= 1 && ((std::string) "") != bufArray[0])
		{
			command = bufArray[0];

			if(((std::string) "deposit") == command)
			{   
				if(bufArray.size() == 3)
				{
					if(processDeposit (bufArray[1], bufArray[2])) {
						std::cout << "Deposit [ " << bufArray[1] << " ]: $ " << bufArray[2] << "\n";
					}
					else {
						std::cout << "Deposit Unsuccesful\n";
					}
				}
				else
				{
					std::cout << "Usage: deposit [username] [amount]\n";
				}
			} 
			else if(((std::string) "balance") == command)
			{    
				if(bufArray.size() == 2)
				{
					float flag = bankBalance(bufArray[1]);
					if(flag >= 0) {
						std::cout << "Balance [ " << bufArray[1] << " ]: $ " << flag << "\n";
					}
					else {
						std::cout << "Balance Unsuccesful\n";
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

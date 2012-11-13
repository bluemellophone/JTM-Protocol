/**
  @file bank.cpp
  @brief Top level bank implementation file
 */

#include "util.h"
#include "account.h"

void* client_thread(void* arg);
void* console_thread(void* arg);


void* formBankPacket(char packet[], std::string command, std::string status, std::string atmNonce, std::string bankNonce)
{
    char delim = ',';
    packet[0] = '\0';
    strcpy(packet,command.c_str());
    packet[command.length()] = delim;
    
    int len = command.length() + 1;
    for(unsigned int i = 0; i < status.length(); ++i)
    {
        packet[len + i] = status[i];  //add username to packet
    }

    len += status.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < atmNonce.length(); ++i)
    {
        packet[len + i] = atmNonce[i];   //add atm nonce to packet
    }
    
    len += atmNonce.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < bankNonce.length(); ++i)
    {
        packet[len + i] = bankNonce[i];   //add bank nonce to packet
    }
    
    len += bankNonce.length();
    packet[len] = delim;
    len++;
    // Packet data has now been added. For the remaining amount of data, fill in random data.
    
    std::string randomString = getRandom(1023 - 128 - 1 - len);
    for(unsigned int i = 0; i < randomString.length(); ++i)
    {
        packet[len + i] = randomString[i];
    }
    len += randomString.length();
    packet[len] = delim;
    len++;

    std::string hashString = SHA512HashString((std::string) command + "," + status + "," + atmNonce + "," + bankNonce + "," + randomString);    
    for(unsigned int i = 0; i < hashString.length(); ++i)
    {
        packet[len + i] = hashString[i];
    }

    packet[1023] = '\0';
}

/* Begin definition of account functions */

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
		if (it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance()) {
			it->reduce_balance(b);
			return true;
		}
	}
	return false;
}

bool processTransfer (std::vector<std::string> info)
{
	//amount 4, rcpt 5
	float b = (float)atof(info.at(4).c_str());
	if (b > 1000.00) {
		return false;
	}

	std::vector<Account>::iterator it;
	for (it = Database.begin(); it != Database.end(); it++) {
		if (it->get_un() == info.at(1) && it->get_logged_in() && b <= it->get_balance()) {
			it->reduce_balance(b);
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
int main(int argc, char* argv[])
{
	srand(812301230);

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

	//printf("[bank] client ID #%d connected\n", csock);
	printf("[bank] client ID #%ld connected\n", csock);

	//input loop
	int length;
	char packet[1024];
	std::string bankNonce = "";
	std::vector<std::string> bufArray;
	std::string command;
	std::string recievedHash;
	std::string recievedHashedData;
	std::string calculatedHash;
	while(1)
	{
		bufArray.clear();
		recievedHash = "";
		recievedHashedData = "";
		calculatedHash = "";

		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
		{
			break;
		}	
		if(length >= 1024)
		{
			printf("[bank] packet too long\n");
			break;
		}
		if(length != recv(csock, packet, length, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}
		else if(length == 1023)
		{
			//printf("[bank] Recieved ATM Packet (Length %d): %s\n", (int) ((std::string) packet).length(), packet);
			bufArray = split((std::string) packet, ',', bufArray);
			command = bufArray[0];
		}

		//TODO: process packet data
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
				if((bankNonce == "" && bufArray[7] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") || bankNonce == bufArray[7])
				{
					bankNonce = getRandom(32);

					if(((std::string) "login") == command) //if command is 'login'
					{   
						bool flag = login (bufArray);
						if (flag) {
							formBankPacket(packet, command, "login of " + bufArray[1], bufArray[6], bankNonce);
						}
						else {
							formBankPacket(packet, "error", "ATM Login not valid", bufArray[6], bankNonce);
						}
					} 
					else if(((std::string) "balance") == command) //if command is 'login'
					{   
						float flag = checkBalance (bufArray);
						if (flag >= 0) {
							formBankPacket(packet, command, "balance of " + bufArray[1], bufArray[6], bankNonce);
						}
						else {
							formBankPacket(packet, "error", "ATM Balance not valid", bufArray[6], bankNonce);
						}
					} 
					else if(((std::string) "withdraw") == command) //if command is 'login'
					{   
						bool flag = processWithdraw (bufArray);
						if (flag) {
							formBankPacket(packet, command, "withdraw of " + bufArray[1] + "  amount: " + bufArray[4], bufArray[6], bankNonce);
						}
						else {
							formBankPacket(packet, "error", "ATM Withdraw not valid", bufArray[6], bankNonce);			
						}
					}
					else if(((std::string) "transfer") == command) //if command is 'login'
					{   
						bool flag = processTransfer (bufArray);
						if (flag) {
							formBankPacket(packet, command, "transfer of " + bufArray[1] + "  amount: " + bufArray[4] + "  recipient: " + bufArray[5], bufArray[6], bankNonce);
						}
						else {
							formBankPacket(packet, "error", "ATM Transfer not valid", bufArray[6], bankNonce);
						}
					}  
					else if(((std::string) "logout") == command) //if command is 'login'
					{   
						formBankPacket(packet, command, "logout of " + bufArray[1], bufArray[6], bankNonce);
					}
				}
				else
				{
					formBankPacket(packet, "error", "ATM Nonce not valid", bufArray[6], bankNonce);
				}
			}
			else
			{
				formBankPacket(packet, "error", "ATM Hash not valid", bufArray[6], bankNonce);
			}
		} 
		else
		{
			// Error: Command sent from ATM not recognized.
			formBankPacket(packet, "error", "ATM Command not valid", bufArray[6], bankNonce);
		}

		//send the new packet back to the client
		if(sizeof(int) != send(csock, &length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}
	}
	
	//printf("[bank] client ID #%d disconnected\n", csock);
	printf("[bank] client ID #%ld disconnected\n", csock);

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

			if(((std::string) "deposit") == command) //if command is 'login'
			{   
				if(bufArray.size() == 3)
				{
					cout << "Deposited " << bufArray[2] << " into " << bufArray[1] << "'s account\n";
				}
				else
				{
					cout << "Usage: deposit [username] [amount]\n";
				}
			} 
			else if(((std::string) "balance") == command) //if command is 'login'
			{    
				if(bufArray.size() == 2)
				{
					cout << "Balance for " << bufArray[1] << "\n";
				}
				else
				{
					cout << "Usage: balance [username]\n";
				}
			} 
			else
			{
				cout << "Command '" << command << "' not recognized.\n";
			}
		}
		else
		{
			cout << "Usage: [command] [argument...]\n";
		} 

	}
}

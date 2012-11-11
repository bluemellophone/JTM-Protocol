/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <vector>
#include <sstream>
#include <iostream>
	

using std::cout;
using std::cin;
using std::endl;

void* client_thread(void* arg);
void* console_thread(void* arg);

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) 
{
    std::stringstream ss(s+' ');
    std::string item;
    while(std::getline(ss, item, delim)) 
    {
        if(item != "")
        {
            elems.push_back(item.substr(0,32));   
        }
    }
    return elems;
}

std::string getRandom(int length)
{   
    std::string retStr = "";

    for(unsigned int i = 0; i < length; ++i)
    {
        retStr += ((rand() % 74) + '0');
    }
    
    return retStr;
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

	int csock = (int)arg;
	//long unsigned int csock = (long unsigned int)arg;
	
	printf("[bank] client ID #%d connected\n", csock);
	//printf("[bank] client ID #%ld connected\n", csock);
	
	//input loop
	int length;
	char packet[1024];
	std::string response = "";
	std::string bankNonce = "";
	std::vector<std::string> bufArray;
	std::string command;
	while(1)
	{
		bufArray.clear();

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
			printf("[bank] Recieved ATM Packet (Length %d): %s\n", length, packet);
			packet[strlen(packet)-1] = '\0';  //trim off trailing newline
			bufArray = split((std::string) packet, ',', bufArray);
	    	command = bufArray[0];
		}
		
		//TODO: process packet data
		packet[0] = '\0';
        
        if(bufArray.size() == 9)
		{

			if((bankNonce == "" && bufArray[7] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") || bankNonce == bufArray[7])
			{
				bankNonce = getRandom(32);

				// Don't put commas in responses!!! 

				if(((std::string) "login") == command) //if command is 'login'
		        {   
		    		response = command + "," + "login of " + bufArray[1];
		        } 
		        else if(((std::string) "balance") == command) //if command is 'login'
		        {   
		    		response = command + "," + "balance of " + bufArray[1];
		        } 
		        else if(((std::string) "withdraw") == command) //if command is 'login'
		        {   
		    		response = command + "," + "withdraw of " + bufArray[1] + "  amount: " + bufArray[4];
		        }
		        else if(((std::string) "transfer") == command) //if command is 'login'
		        {   
		    		response = command + "," + "transfer of " + bufArray[1] + "  amount: " + bufArray[4] + "  recipient: " + bufArray[5];
		        }  
		        else if(((std::string) "logout") == command) //if command is 'login'
		        {   
		    		response = command + "," + "logout of " + bufArray[1];
		        }

		        response += "," + bufArray[6] + "," + bankNonce;
		        response += "," + getRandom(1023 - 2 - response.length());
	    	}
	    	else
	    	{
    			response = "error,ATM Nonce not valid,0,0";	
		        response += "," + getRandom(1023 - 2 - response.length());
	    	}
	    } 
        else
        {
        	// Error: Command sent from ATM not recognized.
    		response = "error,ATM Command not valid,0,0";	
		    response += "," + getRandom(1023 - 2 - response.length());
        }

        // Put response into the packet
	    for(int i = 0; i < response.length(); i++)
		{
			packet[i] = response[i];
		}
		packet[response.length()] = '\0';

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

	printf("[bank] client ID #%d disconnected\n", csock);
	//printf("[bank] client ID #%ld disconnected\n", csock);
	
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
	                cout << "Usage: deposit [username]\n";
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

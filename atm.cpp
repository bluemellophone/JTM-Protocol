/**
    @file atm.cpp
    @brief Top level ATM implementation file
 */

#include "util.h"

int getch() 
{
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}

std::string getPin(std::string prompt)
{
    std::string pin;
    unsigned char ch = 0;

    cout << prompt;
    while((ch = getch()) != 10 && pin.length() <= 6) // Enter
    {
        if(ch == 127) // Backspace
        {
            if(pin.length() != 0)
            {
                cout <<"\b \b";
                pin.resize(pin.length() - 1);
            }
        }
        else if('0' <= ch && ch <= '9')
        {
            pin += ch;
            cout << '*';
        }
    }

    printf("\n");
  
    return pin;
}

void* formATMHandshake(char packet[], std::string atmNonce)
{
    std::vector<std::string> tempVector;
    tempVector.push_back((std::string) "handshake");
    tempVector.push_back(atmNonce);
    formPacket(packet, 512, tempVector);
}

void* formATMPacket(char packet[], std::string command, std::string username, std::string cardHash, std::string pin, std::string item1, std::string item2, std::string atmNonce, std::string bankNonce)
{
    std::vector<std::string> tempVector;
    tempVector.push_back(command);
    tempVector.push_back(username);
    tempVector.push_back(cardHash);
    tempVector.push_back(pin);
    tempVector.push_back(item1);
    tempVector.push_back(item2);
    tempVector.push_back(atmNonce);
    tempVector.push_back(bankNonce);
    formPacket(packet, 1023, tempVector);
}

int main(int argc, char* argv[])
{
    char packet[1024];
    char epacket[1408];
    char hpacket[1041];
    char buf[50];
    std::vector<std::string> bufArray;
    
    std::string command;
    std::string username;
    std::string cardHash;
    std::string pin;
    std::string item1;
    std::string item2;
    std::string atmNonce;
    std::string bankNonce;
    std::string temp; 
    std::string status;

    std::string sessionAESKey;
    std::string sessionAESBlock;
    std::string encryptedPacket;
    std::string decryptedPacket;
    std::string errorString = "Error.  Please contact the service team.\n";

    int length;
    int userTimeout = 0;
    int messageTimeout = 0;
    int sessionTimeout = 0; 

    bool sendPacket = false;
    bool printError = false;
    bool userLoggedIn = false;
    bool validHandshake = false;
    
    if(argc != 2)
    {
        printf("Usage: atm proxy-port\n");
        return -1;
    }
    
    //socket setup
    unsigned short proxport = atoi(argv[1]);
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!sock)
    {
        printf("fail to create socket\n");
        return -1;
    }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxport);
    unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
    ipaddr[0] = 127;
    ipaddr[1] = 0;
    ipaddr[2] = 0;
    ipaddr[3] = 1;
    if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
    {
        printf("fail to connect to proxy\n");
        return -1;
    }

    while(1)
    {
        sendPacket = false;
        printError = false;
        command = "";
        item1 = "NOT USED";
        item2 = "NOT USED";
        buf[0] = '\0';
        packet[0] = '\0';
        epacket[0] = '\0';
        hpacket[0] = '\0';
        
        // Print the prompt
        printf("atm> ");
        fgets(buf, 49, stdin);
        buf[strlen(buf)-1] = '\0';  //trim off trailing newline
        
        // Parse data
        bufArray.clear();
        bufArray = split((std::string) buf, ' ', bufArray);
       
        //input parsing
        if(bufArray.size() >= 1 && ((std::string) "") != bufArray[0])
        {
            if(time(NULL) - userTimeout <= 90 || !userLoggedIn)
            { 
                command = bufArray[0];
            }
            else
            {
                command = "timeout";
            }

            userTimeout = time(NULL);
            
            if(time(NULL) - sessionTimeout > 180)
            { 
                validHandshake = false;
            }
            
            if(((std::string) "login") == command)
            {   
                if(!userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {   
                        temp = bufArray[1];
                        temp = temp.substr(0,32);
                        std::transform(temp.begin(), temp.end(), temp.begin(), ::tolower);
                        temp = toAlpha(temp);
                        std::string cardFilename = "cards/" + temp + ".card";
                        std::ifstream cardFile(cardFilename.c_str());

                        if(cardFile)
                        {
                            sendPacket = true; 

                            username = temp;

                            cardHash = getCardHash(cardFilename);

                            pin = getPin("PIN: ");
                            pin = pin.substr(0,6);
                            while(pin.length() < 6)
                            {
                                pin = pin + "0";
                            }
                            pin = toNumbers(pin);
                        }
                        else
                        {
                            temp = "";
                            cout << "ATM card not found.\n";
                        }
                    }
                    else
                    {
                        cout << "Usage: login [username]\n";
                    }
                }
                else
                {
                    cout << "User already logged in.  Due to this action, the current user has now been logged out.  \n"; 

                    sendPacket = true; 
                    command = "logout";
                }
            } 
            else if(((std::string) "balance") == command)
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1)
                    {
                        sendPacket = true; 
                    }
                    else
                    {
                        cout << "Usage: balance\n";
                    }
                }
                else
                {
                    cout << "User not logged in.  \n";
                }
            } 
            else if(((std::string) "withdraw") == command)
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 2 && isNumbersOnly(bufArray[1]))
                    {
                        sendPacket = true;
                        item1 = bufArray[1];
                    }
                    else
                    {
                        cout << "Usage: withdraw [whole dollar amount]\n";
                    }
                }
                else
                {
                    cout << "User not logged in.  \n";
                }
            } 
            else if(((std::string) "transfer") == command)
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 3 && isNumbersOnly(bufArray[1]))
                    {
                        sendPacket = true;
                        item1 = bufArray[1];
                        item2 = bufArray[2];
                    }
                    else
                    {
                        cout << "Usage: transfer [whole dollar amount] [username]\n";
                    }
                }
                else
                {
                    cout << "User not logged in.  \n";
                }
            } 
            else if(((std::string) "logout") == command || ((std::string) "timeout") == command)
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1 || ((std::string) "timeout") == command)
                    {
                        if(((std::string) "timeout") == command)
                        {
                            cout << "Timeout: user inactivity has caused a timeout, the current user has now been logged out.\n";
                        }
                        sendPacket = true; 
                        command = "logout";
                    }
                    else
                    {
                        cout << "Usage: logout\n";
                    }
                }
                else
                {
                    cout << "User not logged in.  \n";
                }
            }
            else
            {
                cout << "Command '" << command << "' not recognized.\n";
            }

            if(sendPacket)
            {
                if(!validHandshake)
                {
                    bankNonce = "";
                    sessionAESKey = "";
                    sessionAESBlock = "";
                    atmNonce = getRandom(32);
                    
                    formATMHandshake(hpacket, atmNonce);
	            encryptedPacket = encryptRSAPacket((std::string) hpacket, "keys/bank.pub");
                    
                    for(int i = 0; i < encryptedPacket.length(); i++)
                    {
                        hpacket[i] = encryptedPacket[i];
                    }
                    
                    length = strlen(hpacket);
                    
                    if(sizeof(int) != send(sock, &length, sizeof(int), 0))
                    {
                        break;
                    }
                    if(length != send(sock, (void*)hpacket, length, 0))
                    {
                        break;
                    }
                    
                    hpacket[0] = '\0';
                    
                    if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
                    {
                        break;
                    }
                    if(length != recv(sock, hpacket, length, 0))
                    {
                        break;
                    }
                    if(length == 1040)
                    {
                        decryptedPacket = decryptRSAPacket((std::string) hpacket, "keys/atm");
                        
                        bufArray.clear();
                        bufArray = split(decryptedPacket, ',', bufArray);

                        if(bufArray.size() == 7)
                        {   
                            if(compareSHA512Hash(bufArray[6], bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4] + "," + bufArray[5]))
                            {
                                if(atmNonce == bufArray[1])
                                {
                                    atmNonce = getRandom(32);
                                    if(((std::string) "handshake") == bufArray[0])
                                    {   
                                        bankNonce = bufArray[2];
                                        sessionAESKey = bufArray[3];
                                        sessionAESBlock = bufArray[4];
                                        validHandshake = true;
                                        sessionTimeout = time(NULL);
                                    } 
                                    else if(((std::string) "error") == bufArray[0])
                                    { 
                                        printError = true;
                                    }
                                }
                                else
                                {
                                    printError = true;
                                }

                            }
                            else
                            {
                                printError = true;
                            }
                        } 
                        else
                        {
                            printError = true;
                        }
                    }
                }

                if(validHandshake)
                {
                    messageTimeout = time(NULL);
                    atmNonce = getRandom(32);
                    formATMPacket(packet, command, username, cardHash, pin, item1, item2, atmNonce, bankNonce);
		    encryptedPacket = encryptAESPacket((std::string) packet, sessionAESKey, sessionAESBlock);
                    
                    for(int i = 0; i < encryptedPacket.length(); i++)
                    {
                        epacket[i] = encryptedPacket[i];
                    }

                    
                    length = encryptedPacket.length();
                    if(sizeof(int) != send(sock, &length, sizeof(int), 0))
                    {
                        printf("fail to send packet length\n");
                        break;
                    }
                    if(length != send(sock, (void*)epacket, length, 0))
                    {
                        printf("fail to send packet\n");
                        break;
                    }
                    
                    epacket[0] = '\0';
                    packet[0] = '\0';
                     
                    if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
                    {
                        printf("fail to read packet length\n");
                        break;
                    }
                    if(length > 1408)
                    {
                        printf("packet too long\n");
                        
                    }
                    if(length != recv(sock, epacket, length, 0))
                    {
                        printf("fail to read packet\n");
                        break;
                    }
                    else if(length == 1408)
                    {
                        if(time(NULL) - messageTimeout < 30) // Bank Response needs to be in less that 30 seconds.
                        {    
			decryptedPacket = decryptAESPacket((std::string) epacket, sessionAESKey, sessionAESBlock);
                            
                            bufArray.clear();
                            bufArray = split(decryptedPacket, ',', bufArray);

                            if(bufArray.size() == 6)
                            {
                                if(compareSHA512Hash(bufArray[5], bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4]))
                                {
                                    if(atmNonce == bufArray[2])
                                    {
                                        atmNonce = getRandom(32);
                                        command = bufArray[0];
                                        status = bufArray[1];
                                        bankNonce = bufArray[3];
                                        if(((std::string) "login") == command)
                                        {   
                                            userLoggedIn = true;
                                            cout << status;
                                        } 
                                        else if(((std::string) "balance") == command)
                                        { 
                                            cout << status;
                                        } 
                                        else if(((std::string) "withdraw") == command)
                                        {   
                                            cout << status;
                                        }
                                        else if(((std::string) "transfer") == command)
                                        {   
                                            cout << status;
                                        }  
                                        else if(((std::string) "logout") == command)
                                        {   
                                            cout << status;
                                            userTimeout = 0;
                                            messageTimeout = 0;
                                            sessionTimeout = 0;
                                            sessionAESKey = "";
                                            sessionAESBlock = "";
                                            validHandshake = false;
                                            userLoggedIn = false; 
                                            username = ""; 
                                            cardHash = ""; 
                                            pin = "";
                                        } 
                                        else if(((std::string) "error") == command)
                                        {   
                                            cout << status;
                                        }
                                    }
                                    else
                                    {
                                        printError = true;
                                    }
                                }
                                else
                                {
                                    printError = true;
                                }
                            } 
                            else
                            {
                                printError = true;
                            }

                            cout << endl;
                        }
                        else
                        {
                            printError = true;
                        }
                    }
                }
                else
                {
                    printError = true;
                }
            }

            if(printError)
            {
                cout << errorString;
            }
        }
        else
        {
            cout << "Usage: [command] [argument...]\n";
        } 
    }
    
    //cleanup
    close(sock);
    return 0;
}

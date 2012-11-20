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

std::string getPin(const char *prompt)
{
    std::string pin;
    unsigned char ch = 0;

    cout << prompt;
    while((ch=getch()) != 10) // Enter
    {
        if(ch == 127) // Backspace
        {
            if(pin.length() != 0)
            {
                cout <<"\b \b";
                pin.resize(pin.length() - 1);
            }
        }
        else
        {
            pin += ch;
            cout << '*';
        }
    }

    printf("\n");
  
    return pin;
}

void* formATMHandshake(char packet[], std::string command, std::string atmNonce)
{
    std::vector<std::string> tempVector;
    tempVector.push_back(command);
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
    srand(918234098);

    char packet[1024]; // Pre-ecrypted Packet
    char epacket[1408]; // Encrypted Packet
    char hpacket[1041]; // Handshake Packet
    char buf[80];
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

    std::string sessionAESKey;
    std::string sessionAESBlock;
    std::string recievedHash;
    std::string recievedHashedData;
    std::string calculatedHash;
    std::string encryptedPacket;
    std::string decryptedPacket;   
    std::string encryptedRSA;
    std::string decryptedRSA;


    int length = 0;
    int sendPacket = 0;
    int userTimeout = 0;
    int messageTimeout = 0;
    int sessionTimeout = 0; 

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
        sendPacket = 0;
        command = "";
        item1 = "NOT USED";
        item2 = "NOT USED";
        buf[0] = '\0';
        packet[0] = '\0';
        bufArray.clear();

        // Print the prompt
        printf("atm> ");
        fgets(buf, 79, stdin);
        buf[strlen(buf)-1] = '\0';  //trim off trailing newline
        
        // Parse data
        bufArray = split((std::string) buf, ' ', bufArray);
       
        //input parsing
        if(bufArray.size() >= 1 && ((std::string) "") != bufArray[0])
        {
            //cout << "[atm] Time since last command: " << time(NULL) - userTimeout << endl;
            
            if(userTimeout == 0 || time(NULL) - userTimeout <= 90)
            { 
                // User timeout has to be less than 90 seconds to continue
                command = bufArray[0];
            }
            else
            {
                command = "timeout";
            }

            if(time(NULL) - sessionTimeout > 180) // Session timeout happens after 180 seconds.  At that point, generate new session key.
            { 
                validHandshake = false;
            }
            
            userTimeout = time(NULL);
            
            // There exists a command, check the command
            if(((std::string) "login") == command) //if command is 'login'
            {   
                if(!userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {   
                        temp = bufArray[1];
                        temp = temp.substr(0,32);
                        std::transform(temp.begin(), temp.end(), temp.begin(), ::tolower);
                        temp = toAlpha(temp);
                        std::ifstream cardFile(("cards/" + temp + ".card").c_str());

                        if(cardFile)
                        {
                            sendPacket = 1; 

                            username = temp;

                            // obtain card hash
                            cardHash = getCardHash("cards/" + username + ".card");

                            // obtain pin form user
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
                            cout << bufArray[1] <<"'s ATM Card not found.\n";
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

                    sendPacket = 1; 
                    command = "logout";
                }
            } 
            else if(((std::string) "balance") == command) //if command is 'balance'
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1)
                    {
                        sendPacket = 1; 
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
            else if(((std::string) "withdraw") == command) //if command is 'withdraw'
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {
                        sendPacket = 1;
                        item1 = bufArray[1];
                    }
                    else
                    {
                        cout << "Usage: withdraw [amount]\n";
                    }
                }
                else
                {
                    cout << "User not logged in.  \n";
                }
            } 
            else if(((std::string) "transfer") == command) //if command is 'transfer'
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 3)
                    {
                        sendPacket = 1;
                        item1 = bufArray[1];
                        item2 = bufArray[2];
                    }
                    else
                    {
                        cout << "Usage: transfer [amount] [username]\n";
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
                            cout << "Timeout: user inactivity has caused a timeout, the current user has now been logged out.  \n";
                        }
                        sendPacket = 1; 
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

                    formATMHandshake(hpacket, "handshake", atmNonce);

                    encryptedRSA = encryptRSAPacket((std::string) hpacket, "keys/bank.pub");
                    //cout << "[atm] Encrypted Handshake (Length " << encryptedRSA.length() << "): " << endl << encryptedRSA << endl << endl;

                    for(int i = 0; i < encryptedRSA.length(); i++)
                    {
                        hpacket[i] = encryptedRSA[i];
                    }
                    length = encryptedRSA.length();

                    length = strlen(hpacket);
                    if(sizeof(int) != send(sock, &length, sizeof(int), 0))
                    {
                        printf("fail to send packet length\n");
                        break;
                    }
                    if(length != send(sock, (void*)hpacket, length, 0))
                    {
                        printf("fail to send packet\n");
                        break;
                    }
                    
                    hpacket[0] = '\0';
                    
                    if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
                    {
                        printf("fail to read packet length\n");
                        break;
                    }
                    if(length > 1039)
                    {
                        printf("packet too long: %d\n", length);
                        
                    }
                    if(length != recv(sock, hpacket, length, 0))
                    {
                        printf("fail to read packet\n");
                        break;
                    }

                    //cout << "[atm] Recieved Bank Handshake (Length " << strlen(hpacket) << "): " << endl << (std::string) hpacket << endl << endl;
                    if(length == 1039)
                    {

                        decryptedRSA = decryptRSAPacket((std::string) hpacket, "keys/atm");
                        bufArray.clear();
                        bufArray = split(decryptedRSA, ',', bufArray);

                        if(bufArray.size() == 7)
                        {
                            recievedHash = bufArray[6];
                            recievedHash = recievedHash.substr(0, recievedHash.length() - 1);
                            recievedHashedData = bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4] + "," + bufArray[5];
                            calculatedHash = SHA512HashString(recievedHashedData);
                            if(recievedHash == calculatedHash)
                            {
                                if(atmNonce == bufArray[1])
                                {
                                    if(((std::string) "handshake") == bufArray[0]) //if command is 'login'
                                    {   
                                        bankNonce = bufArray[2];
                                        sessionAESKey = bufArray[3];
                                        sessionAESBlock = bufArray[4];
                                        validHandshake = true;
                                        sessionTimeout = time(NULL);
                                    } 
                                    else if(((std::string) "error") == bufArray[0]) //if command is 'balancd'
                                    { 
                                        cout << "Error.  Please contact the service team." << endl;
                                    }
                                }
                                else
                                {
                                    cout << "Error.  Please contact the service team." << endl;
                                }

                            }
                            else
                            {
                                cout << "Error.  Please contact the service team." << endl;
                            }
                        } 
                        else
                        {
                            // Error: Command sent from ATM not recognized.
                            cout << "Error.  Please contact the service team." << endl;
                        }
                    }
                }

                // Only continue if there is a valid handshake
                if(validHandshake)
                {

                    atmNonce = getRandom(32);

                    formATMPacket(packet, command, username, cardHash, pin, item1, item2, atmNonce, bankNonce);
                    
                    //cout << "[atm] Sending ATM Packet (Length " << strlen(packet) << "): " << endl << (std::string) packet << endl << endl;
                    encryptedPacket = encryptAESPacket((std::string) packet, sessionAESKey, sessionAESBlock);
                    // cout << "[atm] Sending ATM Encrypted Packet (Length " << encryptedPacket.length() << "): " << endl << encryptedPacket << endl << endl;

                    for(int i = 0; i < encryptedPacket.length(); i++)
                    {
                        epacket[i] = encryptedPacket[i];
                    }

                    length = encryptedPacket.length();

                    
                    messageTimeout = time(NULL);
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
                        if(time(NULL) - messageTimeout < 1) // Bank Response needs to be in less that 3 seconds.
                        {
                            //printf("[atm] Recieved Bank Encrypted Packet (Length %d): \n%s\n\n", (int) ((std::string) epacket).length(), epacket);
                            decryptedPacket = decryptAESPacket((std::string) epacket, sessionAESKey, sessionAESBlock);
                            //cout << "[atm] Recieved Bank Packet (Length " << decryptedPacket.length() << "): " << endl << decryptedPacket << endl << endl;

                            for(int i = 0; i < decryptedPacket.length(); i++)
                            {
                                packet[i] = decryptedPacket[i];
                            }
                        
                            bufArray.clear();
                            bufArray = split((std::string) packet, ',', bufArray);

                            if(bufArray.size() == 6)
                            {
                                recievedHash = bufArray[5];
                                recievedHash = recievedHash.substr(0, recievedHash.length() - 1);
                                recievedHashedData = bufArray[0] + "," + bufArray[1] + "," + bufArray[2] + "," + bufArray[3] + "," + bufArray[4];
                                calculatedHash = SHA512HashString(recievedHashedData);
                                
                                //cout << recievedHash << " (Length " << recievedHash.length() << ")" << endl;
                                //cout << calculatedHash << " (Length " << calculatedHash.length() << ")" << endl;
                                if(recievedHash == calculatedHash)
                                {
                                    if(atmNonce == bufArray[2])
                                    {
                                        command = bufArray[0];
                                        bankNonce = bufArray[3];
                                        if(((std::string) "login") == command) //if command is 'login'
                                        {   
                                            userLoggedIn = true;
                                            cout << bufArray[1];
                                        } 
                                        else if(((std::string) "balance") == command) //if command is 'balancd'
                                        { 
                                            cout << bufArray[1];
                                        } 
                                        else if(((std::string) "withdraw") == command) //if command is 'withdraw'
                                        {   
                                            cout << bufArray[1];
                                        }
                                        else if(((std::string) "transfer") == command) //if command is 'transfer'
                                        {   
                                            cout << bufArray[1];
                                        }  
                                        else if(((std::string) "logout") == command) //if command is 'logout'
                                        {   
                                            cout << bufArray[1];
                                            userTimeout = 0;
                                            validHandshake = false;
                                            userLoggedIn = false; 
                                            username = ""; 
                                            cardHash = ""; 
                                            pin = "";
                                        } 
                                        else if(((std::string) "error") == command) //if command is 'error'
                                        {   
                                            cout << bufArray[1];
                                        }
                                    }
                                    else
                                    {
                                        cout << "Error.  Please contact the service team.";
                                        if(((std::string) "error") == bufArray[0]) //if command is 'error'
                                        {   
                                            userLoggedIn = false; username = ""; cardHash = ""; pin = "";
                                            cout << bufArray[1];
                                        }
                                    }

                                }
                                else
                                {
                                    cout << "Error.  Please contact the service team.";
                                }
                            } 
                            else
                            {
                                // Error: Command sent from ATM not recognized.
                                cout << "Error.  Please contact the service team.";
                            }

                            cout << endl;
                        }
                        else
                        {
                            // Error: Timeout from Bank Response.
                            cout << "Error.  Please contact the service team.";
                        }
                    }
                }
                else
                {
                    cout << "Error.  Please contact the service team.";
                }
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

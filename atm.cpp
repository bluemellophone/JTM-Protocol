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

void* formPacket(char packet[], std::string command, std::string username, std::string cardHash, std::string pin, std::string item1, std::string item2, std::string atmNonce, std::string bankNonce)
{
    char delim = ',';
    packet[0] = '\0';
    strcpy(packet,command.c_str());
    packet[command.length()] = delim;
    
    int len = command.length() + 1;
    for(unsigned int i = 0; i < username.length(); ++i)
    {
        packet[len + i] = username[i];  //add username to packet
    }
    
    len += username.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < cardHash.length(); ++i)
    {
        packet[len + i] = cardHash[i];   //add card hash to packet
    }

    len += cardHash.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < pin.length(); ++i)
    {
        packet[len + i] = pin[i];   //add pin to packet
    }
    
    len += pin.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < item1.length(); ++i)
    {
        packet[len + i] = item1[i];   //add item1 to packet
    }
    
    len += item1.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < item2.length(); ++i)
    {
        packet[len + i] = item2[i];   //add item2 to packet
    }
    
    len += item2.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < atmNonce.length(); ++i)
    {
        packet[len + i] = atmNonce[i];   //add item2 to packet
    }
    
    len += atmNonce.length();
    packet[len] = delim;
    len++;
    for(unsigned int i = 0; i < bankNonce.length(); ++i)
    {
        packet[len + i] = bankNonce[i];   //add item2 to packet
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

    std::string hashString = SHA512HashString((std::string) command + "," + username + "," + cardHash + "," + pin + "," + item1 + "," + item2 + "," + atmNonce + "," + bankNonce + "," + randomString);    
    for(unsigned int i = 0; i < hashString.length(); ++i)
    {
        packet[len + i] = hashString[i];
    }

    packet[1023] = '\0';
}


int main(int argc, char* argv[])
{
    srand(918234098);

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
    
    bool userLoggedIn = false;
    std::string command = "";
    std::string username = "";
    std::string cardHash = "";
    std::string pin = "";
    std::string atmNonce = getRandom(32);
    std::string bankNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char packet[1024];
    char buf[80];
    int length;
    int sendPacket;
    std::vector<std::string> bufArray;
    int timeout = 0;
    
    //input loop   
    while(1)
    {
        // clean up last packet and buffer
        sendPacket = 0;
        command = "";
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
            //cout << "[atm] Time since last command: " << time(NULL) - timeout << endl;
            
            if(timeout == 0 || time(NULL) - timeout <= 90)
            { 
                // Timeout has to be less than 90 seconds to continue
                command = bufArray[0];
            }
            else
            {
                command = "timeout";
            }
            
            timeout = time(NULL);
            
            // There exists a command, check the command
            if(((std::string) "login") == command) //if command is 'login'
            {   
                if(!userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {   
                        std::ifstream cardFile(("cards/" + bufArray[1] + ".card").c_str());

                        if(cardFile)
                        {
                            sendPacket = 1; // Send packet because valid command
                            username = bufArray[1];

                            // obtain card hash
                            std::string temp((std::istreambuf_iterator<char>(cardFile)),std::istreambuf_iterator<char>());
                            cardHash = temp;
                            cardHash = cardHash.substr(0,32);
                            
                            // obtain pin form user
                            pin = getPin("PIN: ");
                            pin = pin.substr(0,6);
                          
                            formPacket(packet, command, username, cardHash, pin, "NOT USED", "NOT USED", atmNonce, bankNonce);
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

                    sendPacket = 1; // Send packet because valid command
                    formPacket(packet, "logout", username, cardHash, pin, "NOT USED", "NOT USED", atmNonce, bankNonce);

                    userLoggedIn = false; username = ""; cardHash = ""; pin = "";
                }
            } 
            else if(((std::string) "balance") == command) //if command is 'balance'
            {   
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1)
                    {
                        sendPacket = 1; // Send packet because valid command
                        formPacket(packet, command, username, cardHash, pin, "NOT USED", "NOT USED", atmNonce, bankNonce);
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
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {
                        sendPacket = 1;
                        formPacket(packet, command, username, cardHash, pin, bufArray[1], "NOT USED", atmNonce, bankNonce);
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
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 3)
                    {
                        sendPacket = 1;
                        formPacket(packet, command, username, cardHash, pin, bufArray[1], bufArray[2], atmNonce, bankNonce);
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
                        sendPacket = 1; // Send packet because valid command
                        formPacket(packet, "logout", username, cardHash, pin, "NOT USED", "NOT USED", atmNonce, bankNonce);

                        userLoggedIn = false; username = ""; cardHash = ""; pin = "";
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

                //encryptAESPacket(packet);
                


                //This block sends the message through the proxy to the bank. 
                //There are two send messages - 1) packet length and 2) actual packet
                length = strlen(packet);
                
                //cout << "[atm] Sending ATM Packet (Length: " << length << "): " << (std::string) packet << endl;
                
                if(sizeof(int) != send(sock, &length, sizeof(int), 0))
                {
                    printf("fail to send packet length\n");
                    break;
                }
                if(length != send(sock, (void*)packet, length, 0))
                {
                    printf("fail to send packet\n");
                    break;
                }
                
                //Implement timeout for bank response.
                
                if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
                {
                    printf("fail to read packet length\n");
                    break;
                }
                if(length >= 1024)
                {
                    printf("packet too long\n");
                    break;
                }
                if(length != recv(sock, packet, length, 0))
                {
                    printf("fail to read packet\n");
                    break;
                }
                else if(length == 1023)
                {
                    //cout << "[atm] Recieved Bank Packet (Length: " << length << "):" << (std::string) packet << endl;
                
                    bufArray.clear();
                    bufArray = split((std::string) packet, ',', bufArray);

                    if(bufArray.size() == 5)
                    {
                        if(atmNonce == bufArray[2])
                        {
                            atmNonce = getRandom(32);
                            command = bufArray[0];
                            bankNonce = bufArray[3];
                            if(((std::string) "login") == command) //if command is 'login'
                            {   
                                userLoggedIn = true;
                                cout << "User logged in successfully.";
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
                                timeout = 0;
                            }
                        }
                        else
                        {
                            cout << "Error.  Bank Nonce not valid.  ";
                            if(((std::string) "error") == bufArray[0]) //if command is 'error'
                            {   
                                userLoggedIn = false; username = ""; cardHash = ""; pin = "";
                                cout << bufArray[1];
                            }
                        }
                    } 
                    else
                    {
                        // Error: Command sent from ATM not recognized.
                        cout << "Error.  Bank Response not valid " << bufArray.size();
                    }

                    cout << endl;
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

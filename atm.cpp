 /**
    @file atm.cpp
    @brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <termios.h>

using std::cout;
using std::cin;
using std::endl;

//Helper function for getpass() It reads in each character to be masked.
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

// This function returns a vector of strings, which is the prompt split by the delim.
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) 
{
    std::stringstream ss(s+' ');
    std::string item;
    while(std::getline(ss, item, delim)) 
    {
        elems.push_back(item.substr(0,32));
    }
    return elems;
}

//This function prompts for and receives the user-entered PIN (masked with *'s)
std::string getpass(const char *prompt, bool show_asterisk=true)
{
    const char BACKSPACE = 127;
    const char RETURN = 10;

    std::string password;
    unsigned char ch = 0;

    cout << prompt;
    while((ch=getch()) != RETURN)
    {
        if(ch == BACKSPACE)
        {
            if(password.length() != 0)
            {
                if(show_asterisk)
                {
                    cout <<"\b \b";
                }
                password.resize(password.length() - 1);
            }
        }
        else
        {
            password += ch;
            if(show_asterisk)
            {
                cout << '*';
            }
        }
    }

    printf("\n");
  
    return password;
}


void* formPacket(char packet[], std::string command, std::string username, std::string cardHash, std::string pin, std::string item1, std::string item2)
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
    // Packet data has now been added. For the remaining amount of data, fill in random data.
    
    char c;
    for(unsigned int i = (unsigned int) len; i < 1023; ++i)
    {
        srand(((unsigned int)time(NULL)) * ((unsigned int) packet[i-1]) * i);
        c = (rand() % 74) + '0';
        packet[i] = c;   //add random data to packet
    }
        packet[1023] = '\0';

}


int main(int argc, char* argv[])
{
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
    char packet[1024];
    char buf[80];
    int length;
    int sendPacket;
    std::vector<std::string> bufArray;

    //input loop   
    while(1)
    {
        // clean up last packet and buffer
        sendPacket = 0;
        command = "";
        buf[0] = '\0';
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
            command = bufArray[0];
            
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
                            userLoggedIn = true; // THIS NEEDS TO MOVE
                            username = bufArray[1];
                            sendPacket = 1; // Send packet because valid command

                            //obtain card hash
                            std::string temp((std::istreambuf_iterator<char>(cardFile)),std::istreambuf_iterator<char>());
                            cardHash = temp;
                            cardHash = cardHash.substr(0,32);
                            
                            //this block prompts for PIN for login and puts it in the pin var
                            pin = getpass("PIN: ", true);
                            pin = pin.substr(0,6);
                          
                            formPacket(packet, command, username, cardHash, pin, "NOT USED", "NOT USED");
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
                    formPacket(packet, "logout", username, cardHash, pin, "NOT USED", "NOT USED");

                    userLoggedIn = false; username = ""; cardHash = ""; pin = "";
                }
            } 
            else if(((std::string) "balance") == command) //if command is 'login'
            {   
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1)
                    {
                        sendPacket = 1; // Send packet because valid command
                        formPacket(packet, command, username, cardHash, pin, "NOT USED", "NOT USED");
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
            else if(((std::string) "withdraw") == command) //if command is 'login'
            {   
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 2)
                    {
                        sendPacket = 1;
                        formPacket(packet, command, username, cardHash, pin, bufArray[1], "NOT USED");
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
            else if(((std::string) "transfer") == command) //if command is 'login'
            {   
                //this block prompts for 30 char username for login and puts it in the username var
                // Continue as long as there is only one argument.
                if(userLoggedIn)
                {
                    if(bufArray.size() == 3)
                    {
                        sendPacket = 1;
                        formPacket(packet, command, username, cardHash, pin, bufArray[1], bufArray[2]);
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
            else if(((std::string) "logout") == command)
            {   
                if(userLoggedIn)
                {
                    if(bufArray.size() == 1)
                    {
                        sendPacket = 1; // Send packet because valid command
                        formPacket(packet, command, username, cardHash, pin, "NOT USED", "NOT USED");

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
                //This block sends the message through the proxy to the bank. 
                //There are two send messages - 1) packet length and 2) actual packet
                length = strlen(packet);
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
                
                //TODO: do something with response packet

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
                else
                {
                    printf("Recieved Bank Response: %s\n", packet);
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

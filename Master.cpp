#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ifaddrs.h>
#include <string>
#include <iostream>
#include <thread>

#define MASTER_RID 0
#define BACKLOG 10	 // how many pending connections queue will hold
#define MAX_DATA_SIZE 100
#define GROUP_ID 13
#define MAGIC_NUMBER 0x4A6F7921

/*
 * Master.cpp
 * created by Jesse Roach on Oct. 16th 2018
 * receives join request from slave of form
 *   1B     4B (Joy!)
 * | GID | 0x4A6F7921 |
 * sends response to slave of form
 *   1B        4B         1B         4B
 * | GID | 0x4A6F7921 | yourRID | nextSlaveIP |
 * GID is Group ID
 * 0x4A6F7921 is the magic number, an ascii phrase
 * your RID is the slave's assigned Ring ID
 * nextSlaveIP is the ipaddr of the next slave behind the one currently requesting
 * Master will not accept requests that are not both 5 bytes and contain the magic number
 *
 */
unsigned char calculateChecksum(char *dgmIn, int dgmLen);
void displayBuffer(char *Buffer, int length);
void addSlave(unsigned char slaveIP[], int slaveSocketFD);
unsigned char* getOwnIP();

void promptForMessage(int sockfd, addrinfo *pUDP);
void sendMessage(const char *message, int sockfd, addrinfo *pUDP);
void listenForMessages(int sockFD, addrinfo *pUDP);

unsigned char nextSlaveIP[4];
unsigned char nextRID;

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    int sockfdTCP, sock_fdUDP, new_fdTCP;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hintsTCP, hintsUDP, *servinfoTCP, *servinfoUDP, *pTCP, *pUDP;
    struct sockaddr_storage their_addrTCP; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;

    char sTCP[INET6_ADDRSTRLEN];
    char message[5];
    int rvTCP, rvUDP;

    //check for command line args with port number
    if (argc != 2)
    {
        fprintf(stderr,"usage: Master MasterPort# \n");
        exit(1);
    }

    memset(&hintsTCP, 0, sizeof hintsTCP);
    //initialize global values
    unsigned char* ownIP = getOwnIP();
    for (unsigned i = 0; i < 4; i++) {
        nextSlaveIP[i] = ownIP[i];
    }
    nextRID = 1;

    hintsTCP.ai_family = AF_UNSPEC;
    hintsTCP.ai_socktype = SOCK_STREAM;
    hintsTCP.ai_flags = AI_PASSIVE; // use my IP

    if ((rvTCP = getaddrinfo(NULL, argv[1], &hintsTCP, &servinfoTCP)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rvTCP));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(pTCP = servinfoTCP; pTCP != NULL; pTCP = pTCP->ai_next) {
        if ((sockfdTCP = socket(pTCP->ai_family, pTCP->ai_socktype,
                             pTCP->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfdTCP, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfdTCP, pTCP->ai_addr, pTCP->ai_addrlen) == -1) {
            close(sockfdTCP);
            perror("server: bind");
            continue;
        }
        break;
    }

    if (pTCP == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfoTCP); // all done with this structure

    if (listen(sockfdTCP, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    printf("server: waiting for connections...\n");

//////////////////////////UDP server code here//////////////////////////////////
    memset(&hintsUDP, 0, sizeof hintsUDP);
    hintsUDP.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hintsUDP.ai_socktype = SOCK_DGRAM;
    hintsUDP.ai_flags = AI_PASSIVE; // use my IP
    if ((rvUDP = getaddrinfo(NULL, argv[1] , &hintsUDP, &servinfoUDP)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rvUDP));
            return 1;
        }

        // loop through all the results and bind to the first we can
        for(pUDP = servinfoUDP; pUDP != NULL; pUDP = pUDP->ai_next) {
            if ((sock_fdUDP = socket(pUDP->ai_family, pUDP->ai_socktype,
                                 pUDP->ai_protocol)) == -1) {
                perror("ServerUDP: socket");
                continue;
            }
            if (bind(sock_fdUDP, pUDP->ai_addr, pUDP->ai_addrlen) == -1) {
                close(sock_fdUDP);
                perror("ServerUDP: bind");
                continue;
            }
            break;
        }
        if (pUDP == NULL) {
            fprintf(stderr, "ServerUDP: failed to bind socket\n");
            return 2;
        }
        freeaddrinfo(servinfoUDP);

//this thread listens for datagrams from previous node
std::thread listenerThread (listenForMessages, sock_fdUDP, pUDP);
//this thread asks user for message to send and a destination node
//this will continue to happen for the life of the master.
std::thread promptingUserThread (promptForMessage, sock_fdUDP, pUDP);
///////////////////////END UDP//////////////////////////////////////////////////

    while(1) {  // main accept() loop
        sin_size = sizeof their_addrTCP;
        new_fdTCP = accept(sockfdTCP, (struct sockaddr *)&their_addrTCP, &sin_size);
        if (new_fdTCP == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addrTCP.ss_family,
                  get_in_addr((struct sockaddr *)&their_addrTCP),
                  sTCP, sizeof sTCP);
        printf("server: got connection from %s\n", sTCP);

        int message_length = recvfrom(new_fdTCP, message, sizeof(message), 0, (struct sockaddr*) &their_addrTCP, &sin_size);

        if (message_length == -1) {
            printf("Something went wrong while receiving a message from the connection.");
            exit(0);
        }

        if (message[1] != 0x4A || message[2] != 0x6F || message[3] != 0x79 || message[4] != 0x21) {
            printf("The connection's message was incorrect or was corrupted.");
        } else {
            auto *sockIn = (struct sockaddr_in *) &their_addrTCP;

            unsigned char slaveIP[4];
            for (unsigned i = 4; i > 0; i--) {
                slaveIP[4 - i] = (unsigned char) (sockIn->sin_addr.s_addr >> (8 * (4 - i)));
            }
            addSlave(slaveIP, new_fdTCP);
        }
        close(new_fdTCP);  // parent doesn't need this
    }
}
unsigned char calculateChecksum(char *dgmIn, int dgmLen) {
  unsigned short sum = 0;// 16b, to handle overflows
  unsigned char result = 0;//8b
  //get a running sum with overflow accounted for.
  for (int i = 0; i < dgmLen; i++) {
    sum += dgmIn[i];
  }
  //add high order overflow bits to low order bits
  result = (sum & 0xFF) + (sum >> 8);
  result = ~result;
  return result;
}
void displayBuffer(char *Buffer, int length){
    int currentByte, column;

    currentByte = 0;
    printf("\n>>>>>>>>>>>> Content in hexadecimal <<<<<<<<<<<\n");
    while (currentByte < length){
        printf("%3d: ", currentByte);
        column =0;
        while ((currentByte < length) && (column < 10)){
            printf("%2x ",Buffer[currentByte]);
            column++;
            currentByte++;
        }
        printf("\n");
    }
    printf("\n\n");
}

void addSlave(unsigned char slaveIP[], int slaveSocketFD) {
    char toSend[10];
    toSend[0] = GROUP_ID;
    toSend[1] = MAGIC_NUMBER >> 24 & 0xFF;
    toSend[2] = MAGIC_NUMBER >> 16 & 0xFF;
    toSend[3] = MAGIC_NUMBER >> 8 & 0xFF;
    toSend[4] = MAGIC_NUMBER & 0xFF;
    toSend[5] = nextRID;

    for (unsigned i = 0; i < 4; i++) {
        toSend[6 + i] = nextSlaveIP[i];
        nextSlaveIP[i] = slaveIP[i]; //go ahead & update nextSlaveIP just so we don't have to loop twice
    }

    if (write(slaveSocketFD, toSend, sizeof(toSend)) != sizeof(toSend)) {
         printf("An error occurred while sending to the slave.");
         exit(0);
    }

    nextRID++;
}

unsigned char* getOwnIP() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    unsigned char addr[4];

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;

            for (unsigned i = 4; i > 0; i--) {
                addr[4 - i] = (unsigned char) (sa->sin_addr.s_addr >> (8 * (4 - i)));
            }

            if (strcmp(ifa->ifa_name, "em1") == 0) {
                break;
            }
        }
    }

    freeifaddrs(ifap);

    unsigned char *ptr = addr;
    return ptr;
}

void promptForMessage(int sockfd, addrinfo *pUDP) {
    while (true) {
        std::string message;
        unsigned int nodeToSend = 0;

        bool valid = true;
        do {
            std::cout << "Please enter a message to send: ";
            std::cin >> message;

            if (message.length() >= 64) {
                std::cout << "That message is too long.\n\n";
                valid = false;
            }

            if (valid) {
                std::cout << "Please enter the rID of the node to send the message to: ";
                std::cin >> nodeToSend;
            }

            if (nodeToSend >= nextRID) {
                std::cout << "There is no node with that rID.\n\n";
                valid = false;
            }
        } while (!valid);


        unsigned int messageLength = 9 + (unsigned int) message.length();
        char toSend[messageLength];

        toSend[0] = GROUP_ID;
        toSend[1] = MAGIC_NUMBER >> 24 & 0xFF;
        toSend[2] = MAGIC_NUMBER >> 16 & 0xFF;
        toSend[3] = MAGIC_NUMBER >> 8 & 0xFF;
        toSend[4] = MAGIC_NUMBER & 0xFF;
        toSend[6] = nodeToSend;
        toSend[7] = MASTER_RID;
        toSend[8] = 0xFF;

        for (unsigned i = 0; i < message.length(); i++) {
            toSend[9 + i] = message[i];
        }

        toSend[messageLength - 1] = calculateChecksum(toSend, messageLength - 1);

        sendMessage(toSend, sockfd, pUDP);
    }
}

void sendMessage(const char *message, int sockfd, addrinfo *pUDP) {
    const struct sockaddr *addr = pUDP->ai_addr;
    socklen_t len = pUDP->ai_addrlen;

    if (sendto(sockfd, (const void *) message, sizeof(message), 0, addr, len) == -1) {
        perror("Master: sendto");
        exit(1);
    }
}

void listenForMessages(int sockFD, addrinfo *pUDP) {
    char message[MAX_DATA_SIZE];
    int numBytes;
    struct sockaddr_storage their_addr;
    while (true) {
        socklen_t addr_len = sizeof their_addr;
        if ((numBytes = recvfrom(sockFD, message, MAX_DATA_SIZE - 1, 0,
                                 (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        bool valid = true;
        for (unsigned i = 0; i < 4; i++) {
            if (message[1 + i] != MAGIC_NUMBER >> (3 - i) & 0xFF) {
                valid = false;
            }
        }

        if (message[numBytes - 1] != calculateChecksum(message, numBytes - 1)) {
            valid = false;
        }

        if (valid) {
            if (message[6] == MASTER_RID) {
                char messageToDisplay[numBytes - 8];
                for (unsigned i = 0; i < numBytes - 9; i++) {
                    messageToDisplay[i] = message[8 + i];
                }
                messageToDisplay[numBytes - 9] = '\0';

                std::cout << "Message received:\n" << messageToDisplay << std::endl;
            } else {
                auto ttl = (unsigned char) message[5];
                ttl--;

                if (ttl > 0) {
                    message[5] = ttl;
                    sendMessage(message, sockFD, pUDP);
                }
            }
        }
    }
}
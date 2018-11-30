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

#define MASTERRID 0
#define BACKLOG 10	 // how many pending connections queue will hold
#define MAXDATASIZE 100
#define GROUPID 13
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
void initialize();
void addSlave(unsigned char slaveIP[], int slaveSocketFD);
unsigned char* getOwnIP();

void promptForMessage();
void sendMessage(int rID, const std::string& message);
void listenForMessages();

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
    int sockfdTCP, sock_fdUDP, new_fdTCP, new_fdUDP;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hintsTCP, hintsUDP, *servinfoTCP, *servinfoUDP, *pTCP, *pUDP;
    struct sockaddr_storage their_addrTCP, their_addrUDP; // connector's address information
    socklen_t sin_size, addr_len;
    struct sigaction sa;
    int yes=1;

    char sTCP[INET6_ADDRSTRLEN], sUDP[INET6_ADDRSTRLEN];
    char message[5];
    int rvTCP, rvUDP;

    int numbytesTCP, numbytesUDP;
    char tcpBuf[MAXDATASIZE], udpBuf[MAXDATASIZE];

    //check for command line args with port number
    if (argc != 2)
    {
        fprintf(stderr,"usage: Master MasterPort# \n");
        exit(1);
    }

    memset(&hintsTCP, 0, sizeof hintsTCP);

    initialize();

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
////////////////////////////////////////////////////////////////////////////////
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
std::thread listenerThread (listenForMessages);
//this thread asks user for message to send and a destination node
//this will continue to happen for the life of the master.
std::thread promptingUserThread (promptForMessage);
///////////////////////END UDP//////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////


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

        displayBuffer(message, 5);
        if (message[1] != 0x4A || message[2] != 0x6F || message[3] != 0x79 || message[4] != 0x21) {
            printf("The connection's message was incorrect or was corrupted.");
        } else {
            struct sockaddr_in *sockIn = (struct sockaddr_in *) &their_addrTCP;

            unsigned char slaveIP[4];
            for (unsigned i = 4; i > 0; i--) {
                slaveIP[4 - i] = (unsigned char) (sockIn->sin_addr.s_addr >> (8 * (4 - i)));
            }
            addSlave(slaveIP, new_fdTCP);
        }

        //once we have one slave in the ring...
        if (nextRID != MASTERRID) {
          //TODO: Watch for messages from ring.
          //TODO: Prompt user for message and RID
          //TODO: take user input and send message to nextSlaveIP of information
          // 1B  4B         1B  1B      1B        up to 64B  1B
          // GID 0X4A6F7921 TTL RIDDest RIDSource Messagem Checksum
        }
        if (!fork()) {
            close(sockfdTCP);

            if ((numbytesTCP = recv(new_fdTCP, tcpBuf, MAXDATASIZE-1, 0)) == -1) {
                perror("recv");
                exit(1);
            }

            tcpBuf[numbytesTCP] = '\0';

            printf("Server: received '%s'\n",tcpBuf);

            displayBuffer(tcpBuf,numbytesTCP);

            close(new_fdTCP);
            exit(0);
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
    //printf("%x\n", sum);
  }
  //add high order overflow bits to low order bits
  result = (sum & 0xFF) + (sum >> 8);
  //printf("%x\n", result);
  result = ~result;
  //printf("%x\n", result);
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

void initialize() {
    unsigned char* ownIP = getOwnIP();
    for (unsigned i = 0; i < 4; i++) {
        nextSlaveIP[i] = ownIP[i];
    }
    nextRID = MASTERRID;
}

void addSlave(unsigned char slaveIP[], int slaveSocketFD) {
    char toSend[10];
    toSend[0] = GROUPID;
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

void promptForMessage() {
    while (true) {
        std::string message;
        unsigned char ringToSend = 0;

        bool valid = true;
        do {
            std::cout << "Please enter a message to send: ";
            std::cin >> message;

            if (message.length() >= 64) {
                std::cout << "That message is too long.\n\n";
                valid = false;
            }

            if (valid) {
                std::cout << "Please enter the rID of the ring to send the message to: ";
                std::cin >> ringToSend;
            }

            if (ringToSend >= nextRID) {
                std::cout << "There is no ring with that rID.\n\n";
                valid = false;
            }
        } while (!valid);


        unsigned int messageLength = 9 + (unsigned int) message.length();
        char toSend[messageLength];

        toSend[0] = GROUPID;
        toSend[1] = MAGIC_NUMBER >> 24 & 0xFF;
        toSend[2] = MAGIC_NUMBER >> 16 & 0xFF;
        toSend[3] = MAGIC_NUMBER >> 8 & 0xFF;
        toSend[4] = MAGIC_NUMBER & 0xFF;
        toSend[6] = ringToSend;
        toSend[7] = MASTERRID;
        toSend[8] = 0xFF;

        for (unsigned i = 0; i < messageLength; i++) {
            toSend[9 + i] = message[i];
        }

        toSend[messageLength - 1] = calculateChecksum(toSend, messageLength - 1);

        sendMessage(ringToSend, message);
    }
}

void sendMessage(int rID, const std::string& message) {
    //send message to nextSlaveIP with rID and the message
    int responseTML = sizeof(message);
    char *sendBuffer = intsToBytes(responseTML, responseRequestID, responseErrCode, responseResult);
        if ((numbytes = sendto(sockfd, sendBuffer, 7, 0,
                               pUDP->ai_addr, pUDP->ai_addrlen)) == -1) {
            perror("Master: sendto");
            exit(1);
        }
}

void listenForMessages() {
    while (true) {
        //listen for messages
        //once one is received:
            //if the messages' TTL is 0, discard the message
            //otherwise decrement it
            //if the rID = MASTERRID, display the message
            //if not, send it to nextSlaveIP via sendMessage
        printf("\n >>>> Master: listening for a datagram...\n");

        addr_len = sizeof their_addr;
        if ((numbytesUDP = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
                                 (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }
        printf("Master: got packet from %s\n",
               inet_ntop(their_addr.ss_family,
                         get_in_addr((struct sockaddr *)&their_addr),
                         s, sizeof s));
        printf("Master: packet is %d bytes long\n", numbytes);
        buf[numbytes] = '\0';
        printf("Master: packet contains \"%s\"\n", buf);
        displayBuffer(buf,numbytes);
    }
}

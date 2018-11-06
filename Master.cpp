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

#define MASTERRID 0
#define BACKLOG 10	 // how many pending connections queue will hold
#define MAXDATASIZE 100
#define GROUPID 13

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
void displayBuffer(char *Buffer, int length);
void initialize();
void addSlave(unsigned char slaveIP[], int slaveSocketFD);
unsigned char* getOwnIP();

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
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;

    char s[INET6_ADDRSTRLEN];
    char message[5];
    int rv;

    int numbytes;
    char buf[MAXDATASIZE];

    //check for command line args with port number
    if (argc != 2)
    {
        fprintf(stderr,"usage: Master MasterPort# \n");
        exit(1);
    }
    
    initialize();

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, BACKLOG) == -1) {
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

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);

        int message_length = recvfrom(new_fd, message, sizeof(message), 0, (struct sockaddr*) &their_addr, &sin_size);

        if (message_length == -1) {
            printf("Something went wrong while receiving a message from the connection.");
            exit(0);
        }

        displayBuffer(message, 5);
        if (message[1] != 0x4A || message[2] != 0x6F || message[3] != 0x79 || message[4] != 0x21) {
            printf("The connection's message was incorrect or was corrupted.");
        } else {
            struct sockaddr_in *sockIn = (struct sockaddr_in *) &their_addr;

            unsigned char slaveIP[4];
            for (unsigned i = 4; i > 0; i--) {
                slaveIP[4 - i] = (unsigned char) (sockIn->sin_addr.s_addr >> (8 * (4 - i)));
            }
            addSlave(slaveIP, new_fd);


        }

        if (!fork()) {
            close(sockfd);

            if ((numbytes = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
                perror("recv");
                exit(1);
            }

            buf[numbytes] = '\0';

            printf("Server: received '%s'\n",buf);

            displayBuffer(buf,numbytes);

            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }
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
    toSend[1] = 0x4A;
    toSend[2] = 0x6F;
    toSend[3] = 0x79;
    toSend[4] = 0x21;
    toSend[5] = nextRID;

    for (unsigned i = 0; i < 4; i++) {
        toSend[6 + i] = nextSlaveIP[i];
        nextSlaveIP[i] = slaveIP[i]; //go ahead & update nextSlaveIP just so we don't have to loop twice
    }

    //this might need to be changed to UDP
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

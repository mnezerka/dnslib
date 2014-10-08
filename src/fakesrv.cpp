
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>

#include "exception.h"
#include "message.h"

using namespace std;

#define MAX_MSG 2000

const int listenPort = 6666;

int main(int argc, char** argv)
{
    int sockfd,n;
    
    struct sockaddr_in servaddr,cliaddr;
    socklen_t len;
    char mesg[MAX_MSG];

    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    cout << "socket created (" << sockfd << ")" << endl;
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(listenPort);
    bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    cout << "socket binded (port " << listenPort << ")" << endl;

    for (;;)
    {
        n = recv(sockfd, mesg, MAX_MSG, 0);
        cout << "received " << n << "bytes" << endl; 
        dns::Message m;
        m.log_buffer(mesg, n);
        m.decode(mesg, n);

        cout << "-------------------------------------------------------" << endl;
        cout << "Received the following:" << endl;
        cout << m.asString() << endl;
        cout << "-------------------------------------------------------" << endl;

        //sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
    }
    return 0;
}


#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include "exception.h"
#include "message.h"
#include "rr.h"

using namespace std;

#define MAX_MSG 2000

const int listenPort = 6667;

int main(int argc, char** argv)
{
    int sockfd = 0;
    
    struct sockaddr_in servaddr;
    char bufRecv[MAX_MSG];
    char bufSend[MAX_MSG];

    if (argc != 2)
    {
        cout << "usage: fakecli <IP address>" << endl;
        return(1);
    }

    // prepare DNS query message

    dns::Message m;
    m.setQr(dns::Message::typeQuery);

    cout << "-------------------------------------------------------" << endl;
    cout << "Message prepared for sending:" << endl;
    cout << m.asString() << endl;
    cout << "-------------------------------------------------------" << endl;

    // add NAPTR query
    dns::QuerySection *qs = new dns::QuerySection("biloxi.ims");
    qs->setType(dns::RDATA_NAPTR);
    qs->setClass(dns::QCLASS_IN);
    m.addQuery(qs);

    sockfd = socket(AF_INET,SOCK_DGRAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);
    servaddr.sin_port = htons(6666);

    for (unsigned int i = 0; i < 1000000; i++)
    {
        m.setId(i); 

        uint msgSize;
        m.encode(bufSend, MAX_MSG, msgSize);
        //cout << "sending " << msgSize << " bytes" << endl;
        sendto(sockfd, bufSend, msgSize, 0, (struct sockaddr *)&servaddr,sizeof(servaddr));

        //int n = recvfrom(sockfd, bufRecv, MAX_MSG, 0, NULL, NULL);
        recvfrom(sockfd, bufRecv, MAX_MSG, 0, NULL, NULL);

        if (i % 10000 == 0)
            cout << "iterations: " << i << endl;
    }
    return 0;
}




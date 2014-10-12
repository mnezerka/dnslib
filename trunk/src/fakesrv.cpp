
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>

#include "exception.h"
#include "message.h"
#include "rr.h"

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

    unsigned int i = 0;
    for (;;)
    {
        len = sizeof(cliaddr);
        n = recvfrom(sockfd, mesg, MAX_MSG, 0, (struct sockaddr *)&cliaddr, &len);
        //cout << "received " << n << "bytes" << endl; 
        dns::Message m;
        m.decode(mesg, n);

        /*
        cout << "-------------------------------------------------------" << endl;
        cout << "Received message:" << endl;
        cout << m.asString() << endl;
        cout << "-------------------------------------------------------" << endl;
        */

        // change type of message to response
        m.setQr(dns::Message::typeResponse);

        // add NAPTR answer
        dns::ResourceRecord *rr = new dns::ResourceRecord();
        rr->setType(dns::ResourceRecord::typeNAPTR);
        rr->setClass(dns::ResourceRecord::ClassIN);
        rr->setTtl(60);
        dns::RDataNAPTR *rdata = new dns::RDataNAPTR();
        rdata->setOrder(50);
        rdata->setPreference(51);
        rdata->setServices("SIP+D2T");
        rdata->setRegExp("");
        rdata->setReplacement("_sip._tcp.icscf.brn56.iit.ims");
        rr->setRData(rdata);

        m.addAnswer(rr);

        /*
        cout << "-------------------------------------------------------" << endl;
        cout << "Sending message:" << endl;
        cout << m.asString() << endl;
        cout << "-------------------------------------------------------" << endl;
        */

        uint mesgSize;
        m.encode(mesg, MAX_MSG, mesgSize);

        //cout << "sending " << mesgSize << " bytes" << endl;
        sendto(sockfd, mesg, mesgSize, 0, (struct sockaddr *)&cliaddr,sizeof(cliaddr));

        if (i % 10000 == 0)
            cout << "iterations: " << i << endl;
        i++;
    }
    return 0;
}


#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <getopt.h>

#include "exception.h"
#include "message.h"
#include "rr.h"

using namespace std;

#define MAX_MSG 2000

#define VERSION_MAJOR 1
#define VERSION_MINOR 1

#define VERBOSITY_NONE "none"
#define VERBOSITY_BASIC "none"
#define VERBOSITY_ALL "all"

void displayUsage(void)
{
	cout << "Fake DNS server" << endl;
	cout << "usage: fakesrv [-l ip ] [-p port] [-e level] [-h]" << endl;
	cout << " -l ip      ip address for listening (default is '127.0.0.1')" << endl;
	cout << " -p port    port for listening ((default is '53')" << endl;
	cout << " -e level   output verbosity level - 'all', 'basic', 'none' (default is 'all')" << endl;
	cout << " -h         show usage" << endl;
	cout << " -v         get version info" << endl;
}

int main(int argc, char** argv)
{
    enum eVerbosityLevel { verbosityNone, verbosityBasic, verbosityAll} verbosityLevel = verbosityAll;

    // ip address for listening
    std::string listenIp = "127.0.0.1";

    // port for listening
    unsigned int listenPort = 53; 

    // message buffer
    char mesg[MAX_MSG];

	// parse cli arguments 
	static const char *optString = "l:p:e:hv";
	int opt = getopt(argc, argv, optString);
	while(opt != -1) {
		switch(opt) {
			case 'l':
				listenIp = optarg;
				break;
			case 'e':
				if (strcmp(optarg, VERBOSITY_NONE) == 0)
                    verbosityLevel = verbosityNone;
				else if (strcmp(optarg, VERBOSITY_BASIC) == 0)
                    verbosityLevel = verbosityBasic;
                else
                    verbosityLevel = verbosityAll;
				break;
			case 'p':
                {
                    // convert string value to int
                    std::istringstream(optarg) >> listenPort;
                    break;
                }
			case 'h':
				displayUsage();
				return 0;
				break;
			case 'v':
				cout << "fakesrv version " << VERSION_MAJOR << "." << VERSION_MINOR << endl;
				return 0;
				break;

		}
		opt = getopt( argc, argv, optString );
	}

    // create socket descriptor
    int sockfd;
    struct sockaddr_in servaddr,cliaddr;
    socklen_t len;
    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if (sockfd == -1)
	    throw (dns::Exception("Error creating file descriptor"));
    if (verbosityLevel >= verbosityBasic)
        cout << "socket created (" << sockfd << ")" << endl;

    // bind socket to local address and port
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(listenPort);
    if (bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) == -1)
    {
        std::stringstream msg;
		msg  << "Error binding socket, addr: " << listenIp << ":" << listenPort << ", fd:" << sockfd << " (" << strerror(errno) << ")";
	    throw (dns::Exception(msg.str()));
    }
    if (verbosityLevel >= verbosityBasic)
        cout << "socket binded (port " << listenPort << ")" << endl;

    unsigned int i = 0;
    for (;;)
    {
        len = sizeof(cliaddr);
        int n = recvfrom(sockfd, mesg, MAX_MSG, 0, (struct sockaddr *)&cliaddr, &len);
        //cout << "received " << n << "bytes" << endl; 
        dns::Message m;
        m.decode(mesg, n);

        if (verbosityLevel >= verbosityAll)
        {
            cout << "-------------------------------------------------------" << endl;
            cout << "Received message:" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
        }

        // change type of message to response
        m.setQr(dns::Message::typeResponse);

        // add NAPTR answer
        /*
        dns::ResourceRecord *rr = new dns::ResourceRecord();
        rr->setType(dns::RDATA_NAPTR);
        rr->setClass(dns::CLASS_IN);
        rr->setTtl(60);
        dns::RDataNAPTR *rdata = new dns::RDataNAPTR();
        rdata->setOrder(50);
        rdata->setPreference(51);
        rdata->setServices("SIP+D2T");
        rdata->setRegExp("");
        rdata->setReplacement("_sip._tcp.icscf.brn56.iit.ims");
        rr->setRData(rdata);
        m.addAnswer(rr);
        */

        // add A answer
        dns::ResourceRecord *rrA = new dns::ResourceRecord();
        rrA->setType(dns::RDATA_A);
        rrA->setClass(dns::CLASS_IN);
        rrA->setTtl(60);
        dns::RDataA *rdataA = new dns::RDataA();
        dns::uchar ip4[4] = {'\x01', '\x02', '\x03', '\x04' };
        rdataA->setAddress(ip4);
        rrA->setRData(rdataA);
        m.addAnswer(rrA);

        uint mesgSize;
        m.encode(mesg, MAX_MSG, mesgSize);
        if (verbosityLevel >= verbosityAll)
        {
            cout << "-------------------------------------------------------" << endl;
            cout << "Sending message:" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
            cout << "sending " << mesgSize << " bytes" << endl;
        }

        sendto(sockfd, mesg, mesgSize, 0, (struct sockaddr *)&cliaddr,sizeof(cliaddr));

        if (verbosityLevel >= verbosityNone)
        {
            if (i % 10000 == 0)
                cout << "iterations: " << i << endl;
        }
        i++;
    }
    return 0;
}

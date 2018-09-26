/*
 * Copyright (c) 2014 Michal Nezerka
 * All rights reserved.
 *
 * Developed by: Michal Nezerka
 *               https://github.com/mnezerka/
 *               mailto:michal.nezerka@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal with the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimers.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimers in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Michal Nezerka, nor the names of its contributors
 *    may be used to endorse or promote products derived from this Software
 *    without specific prior written permission. 
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.
 */

#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#define VERBOSITY_BASIC "basic"
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
    enum eVerbosityLevel { verbosityNone = 0, verbosityBasic, verbosityAll} verbosityLevel = verbosityAll;

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
                {
                    verbosityLevel = verbosityNone;
                }
                else if (strcmp(optarg, VERBOSITY_BASIC) == 0)
                {
                    verbosityLevel = verbosityBasic;
                }
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

    in_addr listenAddress = {0};
    if (inet_aton(listenIp.c_str(), &listenAddress) == 0)
    {
        cout << "Warning: Can't parse '" << listenIp << "' as an IP, will listen on '0.0.0.0' instead" << endl;
        listenAddress.s_addr = htonl(INADDR_ANY);
    }

    // create socket descriptor
    int sockfd;
    struct sockaddr_in servaddr,cliaddr;
    socklen_t len;
    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if (sockfd == -1)
    {
        cout << "Error creating file descriptor" << endl;
        return 1;
    }
    if (verbosityLevel >= verbosityBasic)
        cout << "socket created (" << sockfd << ")" << endl;

    // bind socket to local address and port
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr=listenAddress;
    servaddr.sin_port=htons(listenPort);
    if (bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) == -1)
    {
        cout  << "Error binding socket, addr: " << inet_ntoa(servaddr.sin_addr) << ":" << listenPort << ", fd:" << sockfd << " (" << strerror(errno) << ")" << endl;
        return 1;
    }
    if (verbosityLevel >= verbosityBasic)
        cout << "socket binded (port " << listenPort << ")" << endl;

    unsigned int i = 0;
    for (;;)
    {
        len = sizeof(cliaddr);
        int n = recvfrom(sockfd, mesg, MAX_MSG, 0, (struct sockaddr *)&cliaddr, &len);
        if (verbosityLevel >= verbosityBasic)
            cout << "Received DNS packet (" << i << ") of size " << n << " bytes" << endl;

        dns::Message m;
        try
        {
            m.decode(mesg, n);
        }
        catch (dns::Exception& e)
        {
            cout << "DNS exception occured when parsing incoming data: " << e.what() << endl;
            continue;
        }

        if (verbosityLevel >= verbosityAll)
        {
            cout << "-------------------------------------------------------" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
        }

        // change type of message to response
        m.setQr(dns::Message::typeResponse);

        // add NAPTR answer
        dns::ResourceRecord *rr = new dns::ResourceRecord();
        rr->setType(dns::RDATA_NAPTR);
        rr->setClass(dns::CLASS_IN);
        rr->setTtl(1);
        dns::RDataNAPTR *rdata = new dns::RDataNAPTR();
        rdata->setOrder(1);
        rdata->setPreference(1);
        rdata->setFlags("u");
        rdata->setServices("SIP+E2U");
        rdata->setRegExp("!.*!domena.cz!");
        rdata->setReplacement("");
        rr->setRData(rdata);
        m.addAnswer(rr);


        /*
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
        */

        uint mesgSize;
        m.encode(mesg, MAX_MSG, mesgSize);

        if (verbosityLevel >= verbosityBasic)
            cout << "Sending DNS packet (" << i << ") of size " << mesgSize << " bytes" << endl;

        if (verbosityLevel >= verbosityAll)
        {
            cout << "-------------------------------------------------------" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
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

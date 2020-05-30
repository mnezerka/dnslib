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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include "exception.h"
#include "message.h"
#include "rr.h"

using namespace std;

#define MAX_MSG 2000

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




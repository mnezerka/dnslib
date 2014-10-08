
#include <iostream>

#include "exception.h"
#include "message.h"

using namespace std;

int main(int argc, char** argv)
{
    //                       00                                      10                                      20                                      30      32          35                  40
    const char packet[] = "\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03\x77\x77\x77\x01\x6c\xc0\x10\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x68\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x63\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x67\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x93";
    //                                                                        3   w   w   w   6   g   o   o   g   l   e   3   c   o   m   0   t   t   c   c  link      type   class             ttl rlength -----------------rdata
    //                     ---------------------------------------header--|--------------------------------------- query1 --------------------------------|-------------------- answer1 ----------------------------------------------------------------------------------

    cout << "decoding packet of length: " << sizeof(packet) << " bytes" << endl;
    dns::Message q;
    q.decode(packet, sizeof(packet));
    cout << q.asString() << endl;

    const char packet1[] = "\x5a\x2e\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x04\x61\x68\x6f\x6a\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
    cout << "decoding packet of length: " << sizeof(packet1) << " bytes" << endl;
    dns::Message m1;
    m1.decode(packet1, sizeof(packet1));
    cout << m1.asString() << endl;

    return 0;
}

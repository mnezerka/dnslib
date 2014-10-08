
#include <iostream>

#include "exception.h"
#include "message.h"

using namespace std;

int main(int argc, char** argv)
{
    //                       00                                      10                                      20                                      30      32                               
    const char packet[] = "\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03\x77\x77\x77\x01\x6c\xc0\x10\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05";
    //                                                                        3   w   w   w   6   g   o   o   g   l   e   3   c   o   m   0   t   t   c   c  link 
    //const char packet[] = { '\xd5', '\xad', 818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93";

    cout << "decoding packet of length: " << sizeof(packet) << " bytes" << endl;

    dns::Message q;
    q.decode(packet, sizeof(packet));
    //q.decode(packet, 24);


    cout << q.asString() << endl;

    return 0;
}

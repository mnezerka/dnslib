#include <iostream>
#include <sstream>
//#include <cstring>
//#include <iomanip>

#include "exception.h"
#include "buffer.h"
#include "qs.h"

using namespace dns;
using namespace std;

string QuerySection::asString()
{
    ostringstream text;
    text << "<DNS Question: " << mQName << " qtype=" << mQType << " qclass=" << mQClass << endl;
    return text.str();
}

void QuerySection::encode(Buffer &buffer)
{
    buffer.putDnsDomainName(mQName);
    buffer.put16bits(mQType);
    buffer.put16bits(mQClass);
}

